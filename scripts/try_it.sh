#!/bin/sh
# Benign local requests to see the honeypot respond (run against YOUR OWN instance only).
H=${1:-http://localhost:8080}
for p in / /login /admin /api/v1/shipments "/track?id=BW1001" /robots.txt /backup.zip; do
  printf '%s -> ' "$p"; curl -s -o /dev/null -w '%{http_code} %{size_download}B %{time_total}s\n' "$H$p"
done
