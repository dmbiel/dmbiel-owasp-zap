#!/usr/bin/env bash
set -euo pipefail

URL="${1:-http://127.0.0.1:3000}"
MAX_ATTEMPTS="${2:-60}"
SLEEP_SECONDS="${3:-2}"

echo "Waiting for target: ${URL}"

for attempt in $(seq 1 "${MAX_ATTEMPTS}"); do
  if curl -fsS "${URL}" > /dev/null; then
    echo "Target is available: ${URL}"
    exit 0
  fi

  echo "Attempt ${attempt}/${MAX_ATTEMPTS}: target is not ready yet"
  sleep "${SLEEP_SECONDS}"
done

echo "Target did not become available: ${URL}"
docker compose logs juice-shop || true
exit 1
