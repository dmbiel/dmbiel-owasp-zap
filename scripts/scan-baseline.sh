#!/usr/bin/env bash
set -euo pipefail

mkdir -p reports

docker compose up -d juice-shop
bash scripts/wait-for-http.sh "http://127.0.0.1:3000"
docker compose run --rm zap-baseline

python scripts/assert_zap_findings.py \
  --report reports/zap-baseline.json \
  --min-total-alerts 1 \
  --min-medium-alerts 1
