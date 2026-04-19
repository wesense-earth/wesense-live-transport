# WeSense Live Transport — Bidirectional MQTT ↔ Zenoh P2P
# Build context: parent directory (side-by-side checkout)
# CI checks out wesense-live-transport/ and wesense-ingester-core/ side by side.
#
# Outbound: MQTT decoded/# → sign → Zenoh P2P network
# Inbound:  Zenoh → verify → ClickHouse (received_via=p2p)

FROM python:3.11-slim

WORKDIR /app

# Bust cache when ingester-core or bridge code changes (set by CI via --build-arg)
ARG CACHE_BUST=1

# Copy and install ingester-core (CACHE_BUST above ensures this isn't stale)
COPY wesense-ingester-core/ /tmp/wesense-ingester-core/

# Install gcc, build all pip packages, then remove gcc in one layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir "/tmp/wesense-ingester-core[p2p]" && \
    apt-get purge -y --auto-remove gcc && \
    rm -rf /var/lib/apt/lists/* /tmp/wesense-ingester-core

# Copy application code
COPY wesense-live-transport/bridge.py .
COPY wesense-live-transport/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Copy sample trust list
COPY wesense-live-transport/trust_list.json data/trust_list.json

# Create directories for data, logs, and local keys (self-echo filter)
RUN mkdir -p /app/data /app/logs /app/local-keys

ENV TZ=UTC

ENTRYPOINT ["/app/entrypoint.sh"]
