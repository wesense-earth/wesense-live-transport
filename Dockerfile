# WeSense Zenoh Bridge — P2P Data Receiver
# Build context: parent directory (side-by-side checkout)
# CI checks out wesense-zenoh-bridge/ and wesense-ingester-core/ side by side.
#
# Subscribes to Zenoh, verifies signatures, writes to local ClickHouse.
# Used by the observer persona to receive data from remote stations.

FROM python:3.11-slim

WORKDIR /app

# Copy dependency files first for better layer caching
COPY wesense-ingester-core/ /tmp/wesense-ingester-core/

# Install gcc, build all pip packages, then remove gcc in one layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    pip install --no-cache-dir "/tmp/wesense-ingester-core[p2p]" && \
    apt-get purge -y --auto-remove gcc && \
    rm -rf /var/lib/apt/lists/* /tmp/wesense-ingester-core

# Copy application code
COPY wesense-zenoh-bridge/bridge.py .

# Copy sample trust list
COPY wesense-zenoh-bridge/trust_list.json data/trust_list.json

# Create directories for data, logs, and local keys (self-echo filter)
RUN mkdir -p /app/data /app/logs /app/local-keys

ENV TZ=UTC

CMD ["python", "-u", "bridge.py"]
