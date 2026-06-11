$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path "reports" | Out-Null

docker compose up -d juice-shop

$Url = "http://127.0.0.1:3000"
$Ready = $false

for ($i = 1; $i -le 60; $i++) {
    try {
        Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5 | Out-Null
        $Ready = $true
        break
    }
    catch {
        Write-Host "Attempt $i/60: target is not ready yet"
        Start-Sleep -Seconds 2
    }
}

if (-not $Ready) {
    docker compose logs juice-shop
    throw "Target did not become available: $Url"
}

docker compose run --rm zap-baseline

python scripts/assert_zap_findings.py `
    --report reports/zap-baseline.json `
    --min-total-alerts 1 `
    --min-medium-alerts 1
