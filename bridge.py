#!/usr/bin/env python3
"""
WeSense Zenoh Bridge — P2P Data Receiver

Subscribes to Zenoh, verifies signatures against a trust list,
and writes incoming readings to the local ClickHouse instance.

This is the observer persona's data receiver: it does NOT re-sign readings.
The original ingester's signature is preserved so that observer ClickHouse
contains the same verifiable data as the station's.

Usage:
    python bridge.py
"""

import hashlib
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
from wesense_ingester.signing.trust import TrustStore
from wesense_ingester.registry.config import RegistryConfig
from wesense_ingester.registry.client import RegistryClient
from wesense_ingester.zenoh.config import ZenohConfig
from wesense_ingester.zenoh.subscriber import ZenohSubscriber

# ── Configuration ─────────────────────────────────────────────────────

STATS_INTERVAL = int(os.getenv("STATS_INTERVAL", "60"))
TRUST_FILE = os.getenv("TRUST_FILE", "data/trust_list.json")
SUBSCRIBE_KEY = os.getenv("ZENOH_SUBSCRIBE_KEY", "wesense/v2/live/**")
LOCAL_KEY_DIRS = os.getenv("LOCAL_KEY_DIRS", "/app/local-keys")
PEER_DISCOVERY_INTERVAL = int(os.getenv("PEER_DISCOVERY_INTERVAL", "120"))

# ClickHouse columns (25-column unified schema)
BRIDGE_COLUMNS = [
    "timestamp", "device_id", "data_source", "network_source", "ingestion_node_id",
    "reading_type", "value", "unit",
    "latitude", "longitude", "altitude", "geo_country", "geo_subdivision",
    "board_model", "sensor_model", "deployment_type", "deployment_type_source",
    "transport_type", "deployment_location", "node_name", "node_info", "node_info_url",
    "signature", "ingester_id", "key_version",
    "received_via",
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
    P2P data receiver: subscribe to Zenoh, verify signatures, write to ClickHouse.
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

        # Trust store for signature verification
        self.trust_store = TrustStore(trust_file=TRUST_FILE)
        self.trust_store.load()
        self.logger.info("Trust store loaded from %s", TRUST_FILE)

        # OrbitDB registry (optional — trust sync only, observer doesn't register)
        registry_config = RegistryConfig.from_env()
        if registry_config.enabled:
            self.registry_client = RegistryClient(
                config=registry_config,
                trust_store=self.trust_store,
            )
            self.registry_client.start_trust_sync()
            self.logger.info("OrbitDB trust sync enabled (observer mode)")
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

        # Zenoh subscriber (local zenohd)
        zenoh_config = ZenohConfig.from_env()
        self.subscriber = ZenohSubscriber(
            config=zenoh_config,
            trust_store=self.trust_store,
            on_reading=self._on_reading,
        )

        # Remote peer discovery via OrbitDB node registry
        self._remote_subscribers: dict[str, ZenohSubscriber] = {}
        self._discovery_thread: threading.Thread | None = None
        self._discovery_stop = threading.Event()

        # Stats
        self.stats = {
            "received": 0,
            "written": 0,
            "duplicates": 0,
            "unsigned": 0,
            "self_echo": 0,
        }

    def _start_peer_discovery(self):
        """Start background thread that discovers remote Zenoh routers from OrbitDB."""
        if not self.registry_client:
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
                    on_reading=self._on_reading,
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

    def _on_reading(self, reading_dict, signed_reading):
        """Callback invoked by ZenohSubscriber for each verified reading."""
        self.stats["received"] += 1

        # Self-echo filter: skip readings from this station's own ingesters
        if (
            signed_reading
            and signed_reading.ingester_id in self._local_ingester_ids
        ):
            self.stats["self_echo"] += 1
            return

        device_id = reading_dict.get("device_id", "")
        reading_type = reading_dict.get("reading_type", "")
        timestamp = reading_dict.get("timestamp", 0)

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

        row = (
            ts,
            device_id,
            reading_dict.get("data_source") or "",
            reading_dict.get("network_source") or "",
            reading_dict.get("ingestion_node_id") or "",
            reading_type,
            value,
            reading_dict.get("unit") or "",
            float(reading_dict["latitude"]) if reading_dict.get("latitude") is not None else None,
            float(reading_dict["longitude"]) if reading_dict.get("longitude") is not None else None,
            float(reading_dict["altitude"]) if reading_dict.get("altitude") is not None else None,
            reading_dict.get("geo_country") or "",
            reading_dict.get("geo_subdivision") or "",
            reading_dict.get("board_model") or "",
            reading_dict.get("sensor_model") or "",
            reading_dict.get("deployment_type") or "",
            reading_dict.get("deployment_type_source") or "",
            reading_dict.get("transport_type") or "",
            reading_dict.get("deployment_location"),
            reading_dict.get("node_name"),
            reading_dict.get("node_info"),
            reading_dict.get("node_info_url"),
            signature,
            ingester_id,
            key_version,
            "p2p",
        )
        self.ch_writer.add(row)
        self.stats["written"] += 1

    def print_stats(self):
        sub_stats = self.subscriber.stats
        ch_stats = self.ch_writer.get_stats()
        dedup_stats = self.dedup.get_stats()

        self.logger.info(
            "STATS | received=%d | written=%d | duplicates=%d | self_echo=%d | unsigned=%d | "
            "sub_verified=%d | sub_rejected=%d | ch_written=%d | ch_buffer=%d | remote_peers=%d",
            self.stats["received"],
            self.stats["written"],
            self.stats["duplicates"],
            self.stats["self_echo"],
            self.stats["unsigned"],
            sub_stats.get("verified", 0),
            sub_stats.get("rejected", 0),
            ch_stats.get("total_written", 0),
            ch_stats.get("buffer_size", 0),
            len(self._remote_subscribers),
        )

    def shutdown(self, signum=None, frame=None):
        self.logger.info("Shutting down...")
        self.running = False

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

    def run(self):
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGTERM, self.shutdown)

        self.logger.info("=" * 60)
        self.logger.info("WeSense Zenoh Bridge (P2P Data Receiver)")
        self.logger.info("Subscribing to: %s", SUBSCRIBE_KEY)
        self.logger.info("=" * 60)

        self.subscriber.connect()
        self.subscriber.subscribe(SUBSCRIBE_KEY)

        # Start discovering remote Zenoh peers from OrbitDB node registry
        self._start_peer_discovery()

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
