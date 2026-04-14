#!/usr/bin/env python3
"""
WeSense Zenoh Bridge — Bidirectional MQTT ↔ Zenoh Bridge

Outbound: subscribes to MQTT decoded readings from all local ingesters,
wraps them in a SignedReading envelope preserving the original ingester
signature, and publishes to the Zenoh P2P network.

Inbound: subscribes to Zenoh, verifies signatures against a trust list,
and writes incoming P2P readings to the local ClickHouse instance.

This is the single point where MQTT world meets Zenoh world. Ingesters
only need to publish decoded readings to MQTT — the bridge handles P2P
distribution automatically.

Usage:
    python bridge.py
"""

import hashlib
import json
import logging
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
)

from wesense_ingester import (
    BufferedClickHouseWriter,
    DeduplicationCache,
    setup_logging,
)
from wesense_ingester.clickhouse.writer import ClickHouseConfig
from wesense_ingester.pipeline import (
    CANONICAL_FIELDS,
    CURRENT_CANONICAL_VERSION,
    build_canonical,
    canonical_to_json,
)
from wesense_ingester.proto.signed_reading_pb2 import SignedReading
from wesense_ingester.signing.keys import IngesterKeyManager, KeyConfig
from wesense_ingester.signing.signer import ReadingSigner
from wesense_ingester.signing.trust import TrustStore
from wesense_ingester.registry.config import RegistryConfig
from wesense_ingester.registry.client import RegistryClient
from wesense_ingester.zenoh.config import ZenohConfig
from wesense_ingester.zenoh.publisher import ZenohPublisher
from wesense_ingester.zenoh.subscriber import ZenohSubscriber

try:
    import paho.mqtt.client as mqtt
    _MQTT_AVAILABLE = True
except ImportError:
    _MQTT_AVAILABLE = False

# ── Configuration ─────────────────────────────────────────────────────

STATS_INTERVAL = int(os.getenv("STATS_INTERVAL", "60"))
TRUST_FILE = os.getenv("TRUST_FILE", "data/trust_list.json")
SUBSCRIBE_KEY = os.getenv("ZENOH_SUBSCRIBE_KEY", "wesense/v2/live/**")
LOCAL_KEY_DIRS = os.getenv("LOCAL_KEY_DIRS", "/app/local-keys")
PEER_DISCOVERY_INTERVAL = int(os.getenv("PEER_DISCOVERY_INTERVAL", "120"))
BRIDGE_API_PORT = int(os.getenv("BRIDGE_API_PORT", "5300"))

# MQTT outbound config
MQTT_BRIDGE_ENABLED = os.getenv("MQTT_BRIDGE_ENABLED", "true").lower() in ("true", "1", "yes")
MQTT_BROKER = os.getenv("MQTT_BROKER", "localhost")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_USERNAME = os.getenv("MQTT_USERNAME")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD")
MQTT_SUBSCRIBE_TOPIC = os.getenv("MQTT_SUBSCRIBE_TOPIC", "wesense/decoded/#")

# ClickHouse columns (30-column unified schema)
BRIDGE_COLUMNS = [
    "timestamp", "device_id", "data_source", "data_source_name",
    "network_source", "ingestion_node_id",
    "reading_type", "reading_type_name", "value", "unit",
    "latitude", "longitude", "altitude", "geo_country", "geo_subdivision",
    "board_model", "sensor_model", "calibration_status",
    "deployment_type", "deployment_type_source",
    "transport_type", "location_source",
    "deployment_location", "node_name", "node_info", "node_info_url",
    "signature", "ingester_id", "key_version",
    "received_via",
    "data_license",
    "signing_payload_version",
]


def _scan_local_ingester_ids(scan_dirs: str) -> set[str]:
    """
    Scan directories for PEM key files and derive ingester_ids.

    Walks all subdirectories, loads each .pem as an Ed25519 private key,
    and computes the ingester_id (wsi_ + first 8 hex of SHA-256 of pubkey).
    """
    ids: set[str] = set()
    for scan_dir in scan_dirs.split(","):
        scan_dir = scan_dir.strip()
        if not os.path.isdir(scan_dir):
            continue
        for dirpath, _, filenames in os.walk(scan_dir):
            for fname in filenames:
                if not fname.endswith(".pem"):
                    continue
                pem_path = os.path.join(dirpath, fname)
                try:
                    with open(pem_path, "rb") as f:
                        private_key = load_pem_private_key(f.read(), password=None)
                    pub_bytes = private_key.public_key().public_bytes(
                        encoding=Encoding.Raw, format=PublicFormat.Raw,
                    )
                    digest = hashlib.sha256(pub_bytes).hexdigest()
                    ids.add(f"wsi_{digest[:8]}")
                except Exception:
                    continue
    return ids


class ZenohBridge:
    """
    Bidirectional MQTT ↔ Zenoh bridge.

    Outbound: MQTT decoded/# → preserve signature → Zenoh wesense/v2/live/**
    Inbound:  Zenoh wesense/v2/live/** → verify → ClickHouse (received_via=p2p)
    """

    def __init__(self):
        self.logger = setup_logging("zenoh_bridge")
        self.running = True

        # Self-echo filter: scan local ingester keys to skip own readings
        self._local_ingester_ids = _scan_local_ingester_ids(LOCAL_KEY_DIRS)
        if self._local_ingester_ids:
            self.logger.info(
                "Self-echo filter active — skipping local ingesters: %s",
                ", ".join(sorted(self._local_ingester_ids)),
            )

        # Bridge signing key (auto-generated on first run)
        key_config = KeyConfig(
            key_dir=os.getenv("ZENOH_KEY_DIR", "data/keys"),
            key_file="bridge_key.pem",
        )
        self._key_manager = IngesterKeyManager(config=key_config)
        self._key_manager.load_or_generate()
        self._signer = ReadingSigner(self._key_manager)
        self.logger.info("Bridge signing identity: %s", self._key_manager.ingester_id)

        # Add bridge's own key to self-echo filter
        self._local_ingester_ids.add(self._key_manager.ingester_id)

        # Trust store for signature verification
        self.trust_store = TrustStore(trust_file=TRUST_FILE)
        self.trust_store.load()

        # Add bridge's own key to trust store so the local Zenoh subscriber
        # can verify (and then self-echo filter) the bridge's own outbound readings
        self.trust_store.add_trusted(
            ingester_id=self._key_manager.ingester_id,
            public_key_bytes=self._key_manager.public_key_bytes,
            key_version=self._key_manager.key_version,
        )
        self.logger.info("Trust store loaded from %s (+ bridge key)", TRUST_FILE)

        # OrbitDB registry — register bridge's key + zenoh endpoint for peer discovery
        registry_config = RegistryConfig.from_env()
        if registry_config.enabled:
            self.registry_client = RegistryClient(
                config=registry_config,
                trust_store=self.trust_store,
            )

            # Determine station mode: public (direct) or proxied
            wesense_proxy = os.getenv("WESENSE_PROXY", "")
            announce_addr = os.getenv("ANNOUNCE_ADDRESS", "")
            zenoh_port = os.getenv("PORT_ZENOH", "7447")

            reg_metadata = {}
            if wesense_proxy:
                # Proxied station: all traffic flows through the proxy.
                # Do NOT register zenoh_endpoint — this station is not directly reachable.
                # ANNOUNCE_ADDRESS is ignored when proxied (safety guard for role changes).
                if announce_addr:
                    self.logger.info(
                        "Proxied (WESENSE_PROXY=%s) — ignoring ANNOUNCE_ADDRESS=%s",
                        wesense_proxy, announce_addr,
                    )
                self.logger.info("Station mode: proxied via %s", wesense_proxy)
            elif announce_addr:
                # Public station: directly reachable from the internet.
                reg_metadata["zenoh_endpoint"] = f"tcp/{announce_addr}:{zenoh_port}"
                self.logger.info("Station mode: public (%s:%s)", announce_addr, zenoh_port)
            else:
                self.logger.info("Station mode: local only (no ANNOUNCE_ADDRESS or WESENSE_PROXY)")

            try:
                self.registry_client.register_node(
                    ingester_id=self._key_manager.ingester_id,
                    public_key_bytes=self._key_manager.public_key_bytes,
                    key_version=self._key_manager.key_version,
                    **reg_metadata,
                )

                # Clean up stale Zenoh entries from OrbitDB — remove zenoh_endpoint
                # from any node entries belonging to THIS station. Uses the set of
                # local ingester IDs (scanned from key files) to identify our entries.
                # This handles:
                #   1. Role changes (public → proxied): stale public endpoints
                #   2. Old ingester registrations that embedded Zenoh (pre-decoupling)
                self.registry_client.cleanup_stale_zenoh_entries(
                    own_bridge_id=self._key_manager.ingester_id,
                    local_ingester_ids=self._local_ingester_ids,
                    is_proxied=bool(wesense_proxy),
                )
            except Exception as e:
                self.logger.warning("OrbitDB registration failed (%s), will retry on next trust sync", e)

            self.registry_client.start_trust_sync()
            self.logger.info("OrbitDB registry — trust sync active, bridge registered")
        else:
            self.registry_client = None

        # Dedup cache — mesh flooding protection
        self.dedup = DeduplicationCache()

        # ClickHouse writer
        try:
            self.ch_writer = BufferedClickHouseWriter(
                config=ClickHouseConfig.from_env(),
                columns=BRIDGE_COLUMNS,
            )
        except Exception as e:
            self.logger.error("Failed to connect to ClickHouse: %s", e)
            sys.exit(1)

        # ── Inbound: Zenoh subscriber (receives P2P readings) ──
        zenoh_config = ZenohConfig.from_env()
        self.subscriber = ZenohSubscriber(
            config=zenoh_config,
            trust_store=self.trust_store,
            on_reading=self._on_inbound_reading,
        )

        # Remote peer discovery via OrbitDB node registry
        self._remote_subscribers: dict[str, ZenohSubscriber] = {}
        self._discovery_thread: threading.Thread | None = None
        self._discovery_stop = threading.Event()

        # ── Outbound: MQTT subscriber → Zenoh publisher ──
        self._mqtt_client: mqtt.Client | None = None
        self._mqtt_connected = False
        self.zenoh_publisher: ZenohPublisher | None = None

        if MQTT_BRIDGE_ENABLED and _MQTT_AVAILABLE:
            self.zenoh_publisher = ZenohPublisher(
                config=zenoh_config,
                signer=self._signer,
            )
        elif MQTT_BRIDGE_ENABLED and not _MQTT_AVAILABLE:
            self.logger.warning("MQTT bridge enabled but paho-mqtt not available")

        # Stats
        self.stats = {
            "received": 0,
            "written": 0,
            "duplicates": 0,
            "unsigned": 0,
            "self_echo": 0,
            "mqtt_received": 0,
            "mqtt_published": 0,
            "unsigned_mqtt": 0,
        }

    # ── Outbound: MQTT → Zenoh ────────────────────────────────────────

    def _start_mqtt_subscriber(self):
        """Subscribe to local MQTT decoded readings and forward to Zenoh."""
        if not MQTT_BRIDGE_ENABLED or not _MQTT_AVAILABLE:
            self.logger.info("MQTT→Zenoh outbound bridge disabled")
            return

        self.zenoh_publisher.connect()

        self._mqtt_client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id="wesense-live-transport",
        )

        if MQTT_USERNAME:
            self._mqtt_client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)

        self._mqtt_client.on_connect = self._mqtt_on_connect
        self._mqtt_client.on_disconnect = self._mqtt_on_disconnect
        self._mqtt_client.on_message = self._mqtt_on_message

        try:
            self._mqtt_client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
            self._mqtt_client.loop_start()
            self.logger.info(
                "MQTT outbound bridge connecting to %s:%d (topic: %s)",
                MQTT_BROKER, MQTT_PORT, MQTT_SUBSCRIBE_TOPIC,
            )
        except Exception as e:
            self.logger.error("MQTT connection failed: %s", e)
            self._mqtt_client = None

    def _mqtt_on_connect(self, client, userdata, flags, rc, properties=None):
        self._mqtt_connected = True
        client.subscribe(MQTT_SUBSCRIBE_TOPIC)
        self.logger.info(
            "MQTT outbound bridge connected, subscribed to %s", MQTT_SUBSCRIBE_TOPIC
        )

    def _mqtt_on_disconnect(self, client, userdata, flags, rc, properties=None):
        self._mqtt_connected = False
        self.logger.warning("MQTT outbound bridge disconnected (rc=%s)", rc)

    def _mqtt_on_message(self, client, userdata, msg):
        """Forward decoded MQTT reading to Zenoh, preserving original signature."""
        self.stats["mqtt_received"] += 1

        try:
            reading = json.loads(msg.payload)
        except (json.JSONDecodeError, ValueError):
            return

        if not isinstance(reading, dict) or not reading.get("device_id"):
            return

        # The MQTT message from ReadingPipeline is {**canonical, **sig_fields}.
        # Extract the original signature metadata placed by the ingester.
        sig_hex = reading.get("signature", "")
        orig_ingester_id = reading.get("ingester_id", "")
        orig_key_version = reading.get("key_version", 0)

        if not sig_hex or not orig_ingester_id:
            # Unsigned reading — cannot forward without a valid signature
            self.stats["unsigned_mqtt"] += 1
            return

        if self.zenoh_publisher and self.zenoh_publisher.is_connected():
            # Reconstruct the canonical payload that was signed by the ingester.
            # Use the reading's own signing_payload_version so we reproduce
            # the exact bytes the ingester signed, regardless of what version
            # this bridge itself considers current.
            signing_version = int(reading.get("signing_payload_version") or 1)
            try:
                canonical = build_canonical(reading, version=signing_version)
            except (KeyError, ValueError, TypeError) as e:
                self.logger.debug(
                    "Could not rebuild canonical v%d from MQTT reading: %s",
                    signing_version, e,
                )
                self.stats["unsigned_mqtt"] += 1
                return
            payload_bytes = canonical_to_json(canonical)

            # Wrap in SignedReading protobuf with the ORIGINAL ingester signature
            envelope = SignedReading(
                payload=payload_bytes,
                signature=bytes.fromhex(sig_hex),
                ingester_id=orig_ingester_id,
                key_version=orig_key_version,
            )

            # Publish to Zenoh using the publisher's session directly
            country = (reading.get("geo_country") or "unknown").lower()
            subdivision = (reading.get("geo_subdivision") or "unknown").lower()
            device_id = reading.get("device_id") or "unknown"
            key_expr = self.zenoh_publisher.config.build_key_expr(
                country, subdivision, device_id,
            )

            try:
                pub = self.zenoh_publisher._get_or_create_publisher(key_expr)
                pub.put(envelope.SerializeToString())
                self.stats["mqtt_published"] += 1
            except Exception as e:
                self.logger.error("Failed to publish to Zenoh: %s", e)

    # ── Inbound: Zenoh → ClickHouse ──────────────────────────────────

    def _on_inbound_reading(self, reading_dict, signed_reading):
        """Callback invoked by ZenohSubscriber for each verified reading."""
        self.stats["received"] += 1

        # Self-echo filter: skip readings from this station's own ingesters or bridge
        if (
            signed_reading
            and signed_reading.ingester_id in self._local_ingester_ids
        ):
            self.stats["self_echo"] += 1
            return

        device_id = reading_dict.get("device_id", "")
        reading_type = reading_dict.get("reading_type", "")
        timestamp = reading_dict.get("timestamp", 0)

        # Version skew check — log a warning if we're receiving readings
        # signed under a canonical version we don't understand yet. The
        # reading is still stored (operator may upgrade later and verify then),
        # but visibility is important.
        incoming_version = int(reading_dict.get("signing_payload_version") or 1)
        if incoming_version > CURRENT_CANONICAL_VERSION:
            self.stats.setdefault("newer_version_received", 0)
            self.stats["newer_version_received"] += 1
            # Rate-limit by only logging first occurrence per session per version
            seen_key = f"_warned_newer_v{incoming_version}"
            if not getattr(self, seen_key, False):
                setattr(self, seen_key, True)
                self.logger.warning(
                    "Received reading with signing_payload_version=%d from ingester %s, "
                    "but this station only supports up to v%d. Upgrade to verify newer readings.",
                    incoming_version,
                    reading_dict.get("ingester_id", "?"),
                    CURRENT_CANONICAL_VERSION,
                )

        # Dedup check
        if self.dedup.is_duplicate(device_id, reading_type, timestamp):
            self.stats["duplicates"] += 1
            return

        # Extract signature fields from the signed_reading envelope (preserve original)
        if signed_reading:
            signature = signed_reading.signature.hex()
            ingester_id = signed_reading.ingester_id
            key_version = signed_reading.key_version
        else:
            # Unsigned reading — still store but flag
            self.stats["unsigned"] += 1
            signature = ""
            ingester_id = ""
            key_version = 0

        # Parse timestamp
        try:
            ts = datetime.fromtimestamp(int(timestamp), tz=timezone.utc)
        except (ValueError, TypeError, OSError):
            self.logger.warning("Invalid timestamp %s from %s", timestamp, device_id)
            return

        value = reading_dict.get("value")
        if value is None:
            return

        try:
            value = float(value)
        except (ValueError, TypeError):
            return

        # Map sensor_transport → transport_type (canonical uses sensor_transport,
        # ClickHouse column is transport_type)
        transport_type = reading_dict.get("transport_type") or reading_dict.get("sensor_transport") or ""

        row = (
            ts,
            device_id,
            reading_dict.get("data_source") or "",
            reading_dict.get("data_source_name") or "",
            reading_dict.get("network_source") or "",
            reading_dict.get("ingestion_node_id") or "",
            reading_type,
            reading_dict.get("reading_type_name") or "",
            value,
            reading_dict.get("unit") or "",
            float(reading_dict["latitude"]) if reading_dict.get("latitude") is not None else None,
            float(reading_dict["longitude"]) if reading_dict.get("longitude") is not None else None,
            float(reading_dict["altitude"]) if reading_dict.get("altitude") is not None else None,
            reading_dict.get("geo_country") or "",
            reading_dict.get("geo_subdivision") or "",
            reading_dict.get("board_model") or "",
            reading_dict.get("sensor_model") or "",
            reading_dict.get("calibration_status") or "",
            reading_dict.get("deployment_type") or "",
            reading_dict.get("deployment_type_source") or "",
            transport_type,
            reading_dict.get("location_source") or "",
            reading_dict.get("deployment_location"),
            reading_dict.get("node_name"),
            reading_dict.get("node_info"),
            reading_dict.get("node_info_url"),
            signature,
            ingester_id,
            key_version,
            "p2p",
            reading_dict.get("data_license") or "CC-BY-4.0",
            int(reading_dict.get("signing_payload_version") or 1),
        )
        self.ch_writer.add(row)
        self.stats["written"] += 1

    # ── Peer Discovery ────────────────────────────────────────────────

    def _start_peer_discovery(self):
        """Start background thread that discovers remote Zenoh routers from OrbitDB."""
        if not self.registry_client:
            return

        # Proxied stations don't need peer discovery — all P2P traffic flows
        # through the local zenohd which connects to the proxy station's zenohd.
        if os.getenv("WESENSE_PROXY", ""):
            self.logger.info("Peer discovery skipped (proxied station — traffic flows via zenohd proxy)")
            return

        def _discovery_loop():
            # Initial delay — let local Zenoh settle
            self._discovery_stop.wait(timeout=30)
            while not self._discovery_stop.is_set():
                try:
                    self._discover_peers()
                except Exception as e:
                    self.logger.warning("Peer discovery error: %s", e)
                self._discovery_stop.wait(timeout=PEER_DISCOVERY_INTERVAL)

        self._discovery_thread = threading.Thread(
            target=_discovery_loop, daemon=True, name="zenoh-peer-discovery"
        )
        self._discovery_thread.start()
        self.logger.info(
            "Zenoh peer discovery started (interval=%ds)", PEER_DISCOVERY_INTERVAL
        )

    def _discover_peers(self):
        """Fetch remote zenoh_endpoints from OrbitDB and connect to new ones."""
        endpoints = self.registry_client.discover_zenoh_peers(
            exclude_ids=self._local_ingester_ids,
        )

        # Connect to newly discovered endpoints
        for ep in endpoints:
            if ep in self._remote_subscribers:
                continue

            self.logger.info("Discovered remote Zenoh peer: %s", ep)
            try:
                remote_config = ZenohConfig(
                    enabled=True,
                    mode="client",
                    routers=[ep],
                )
                remote_sub = ZenohSubscriber(
                    config=remote_config,
                    trust_store=self.trust_store,
                    on_reading=self._on_inbound_reading,
                )
                remote_sub.connect()
                if remote_sub.is_connected():
                    remote_sub.subscribe(SUBSCRIBE_KEY)
                    self._remote_subscribers[ep] = remote_sub
                    self.logger.info("Connected to remote Zenoh peer: %s", ep)
                else:
                    self.logger.warning("Failed to connect to remote peer: %s", ep)
            except Exception as e:
                self.logger.warning("Failed to connect to %s: %s", ep, e)

        # Clean up disconnected peers
        for ep, sub in list(self._remote_subscribers.items()):
            if not sub.is_connected():
                self.logger.info("Remote peer disconnected: %s", ep)
                sub.close()
                del self._remote_subscribers[ep]

    # ── Stats & API ───────────────────────────────────────────────────

    def print_stats(self):
        sub_stats = self.subscriber.stats
        ch_stats = self.ch_writer.get_stats()
        dedup_stats = self.dedup.get_stats()

        self.logger.info(
            "STATS | inbound: received=%d written=%d duplicates=%d self_echo=%d unsigned=%d | "
            "outbound: mqtt_received=%d zenoh_published=%d unsigned_mqtt=%d | "
            "sub_verified=%d sub_rejected=%d | ch_written=%d ch_buffer=%d | remote_peers=%d",
            self.stats["received"],
            self.stats["written"],
            self.stats["duplicates"],
            self.stats["self_echo"],
            self.stats["unsigned"],
            self.stats["mqtt_received"],
            self.stats["mqtt_published"],
            self.stats["unsigned_mqtt"],
            sub_stats.get("verified", 0),
            sub_stats.get("rejected", 0),
            ch_stats.get("total_written", 0),
            ch_stats.get("buffer_size", 0),
            len(self._remote_subscribers),
        )

    def shutdown(self, signum=None, frame=None):
        self.logger.info("Shutting down...")
        self.running = False

        # Outbound cleanup
        if self._mqtt_client:
            self._mqtt_client.loop_stop()
            self._mqtt_client.disconnect()
        if self.zenoh_publisher:
            self.zenoh_publisher.close()

        # Inbound cleanup
        self._discovery_stop.set()
        if self._discovery_thread:
            self._discovery_thread.join(timeout=5)
        for sub in self._remote_subscribers.values():
            sub.close()
        self._remote_subscribers.clear()
        if hasattr(self, 'registry_client') and self.registry_client:
            self.registry_client.close()
        if hasattr(self, 'subscriber'):
            self.subscriber.close()
        if hasattr(self, 'ch_writer'):
            self.ch_writer.close()

        self.logger.info("Shutdown complete")

    def _get_stats_json(self) -> bytes:
        """Build JSON stats payload."""
        sub_stats = self.subscriber.stats
        ch_stats = self.ch_writer.get_stats()
        return json.dumps({
            "received": self.stats["received"],
            "written": self.stats["written"],
            "duplicates": self.stats["duplicates"],
            "self_echo": self.stats["self_echo"],
            "unsigned": self.stats["unsigned"],
            "mqtt_received": self.stats["mqtt_received"],
            "mqtt_published": self.stats["mqtt_published"],
            "unsigned_mqtt": self.stats["unsigned_mqtt"],
            "sub_verified": sub_stats.get("verified", 0),
            "sub_rejected": sub_stats.get("rejected", 0),
            "ch_written": ch_stats.get("total_written", 0),
            "ch_buffer": ch_stats.get("buffer_size", 0),
            "remote_peers": len(self._remote_subscribers),
            "remote_endpoints": list(self._remote_subscribers.keys()),
            "mqtt_connected": self._mqtt_connected,
            "bridge_id": self._key_manager.ingester_id,
        }).encode()

    def _start_stats_api(self):
        """Start a lightweight HTTP server exposing bridge stats (stdlib only)."""
        from http.server import HTTPServer, BaseHTTPRequestHandler

        bridge = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/stats":
                    body = bridge._get_stats_json()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_error(404)

            def log_message(self, format, *args):
                pass  # suppress request logging

        server = HTTPServer(("0.0.0.0", BRIDGE_API_PORT), Handler)

        # Wrap with TLS when enabled
        tls_enabled = os.getenv("TLS_ENABLED", "").lower() == "true"
        certfile = os.getenv("TLS_CERTFILE", "")
        keyfile = os.getenv("TLS_KEYFILE", "")
        if tls_enabled and certfile and keyfile and os.path.exists(certfile):
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile, keyfile)
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
            self.logger.info("Stats API listening on port %d (HTTPS)", BRIDGE_API_PORT)
        else:
            self.logger.info("Stats API listening on port %d", BRIDGE_API_PORT)

        thread = threading.Thread(
            target=server.serve_forever,
            daemon=True,
            name="bridge-stats-api",
        )
        thread.start()

    # ── Main Loop ─────────────────────────────────────────────────────

    def run(self):
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGTERM, self.shutdown)

        self.logger.info("=" * 60)
        self.logger.info("WeSense Zenoh Bridge (Bidirectional MQTT ↔ Zenoh)")
        self.logger.info("Inbound:  Zenoh %s → ClickHouse", SUBSCRIBE_KEY)
        if MQTT_BRIDGE_ENABLED:
            self.logger.info("Outbound: MQTT %s → Zenoh", MQTT_SUBSCRIBE_TOPIC)
        self.logger.info("Bridge identity: %s", self._key_manager.ingester_id)
        self.logger.info("=" * 60)

        # Start inbound Zenoh subscriber
        self.subscriber.connect()
        self.subscriber.subscribe(SUBSCRIBE_KEY)

        # Start outbound MQTT→Zenoh bridge
        self._start_mqtt_subscriber()

        # Start discovering remote Zenoh peers from OrbitDB node registry
        self._start_peer_discovery()

        # Start HTTP stats endpoint
        self._start_stats_api()

        try:
            while self.running:
                time.sleep(STATS_INTERVAL)
                self.print_stats()
        except KeyboardInterrupt:
            self.shutdown()
            sys.exit(0)


def main():
    bridge = ZenohBridge()
    bridge.run()


if __name__ == "__main__":
    main()
