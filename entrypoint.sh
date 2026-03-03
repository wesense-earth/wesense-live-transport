#!/bin/sh
# entrypoint.sh — Fix directory ownership then drop to PUID:PGID
set -e

PUID="${PUID:-1000}"
PGID="${PGID:-1000}"

mkdir -p /app/data /app/logs
chown -R "$PUID:$PGID" /app/data /app/logs

exec setpriv --reuid="$PUID" --regid="$PGID" --clear-groups \
    python -u bridge.py "$@"
