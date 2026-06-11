#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate OWASP ZAP JSON report.")
    parser.add_argument("--report", required=True, help="Path to ZAP JSON report.")
    parser.add_argument("--min-total-alerts", type=int, default=1)
    parser.add_argument("--min-medium-alerts", type=int, default=0)
    parser.add_argument("--min-high-alerts", type=int, default=0)
    return parser.parse_args()


def load_report(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Report file does not exist: {path}")

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def extract_alerts(report: dict[str, Any]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []

    sites = report.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]

    if isinstance(sites, list):
        for site in sites:
            site_alerts = site.get("alerts", []) if isinstance(site, dict) else []
            if isinstance(site_alerts, list):
                alerts.extend(alert for alert in site_alerts if isinstance(alert, dict))

    root_alerts = report.get("alerts", [])
    if isinstance(root_alerts, list):
        alerts.extend(alert for alert in root_alerts if isinstance(alert, dict))

    return alerts


def normalize_risk(alert: dict[str, Any]) -> str:
    risk = str(alert.get("riskdesc") or alert.get("risk") or "").lower()
    if "high" in risk:
        return "High"
    if "medium" in risk:
        return "Medium"
    if "low" in risk:
        return "Low"
    if "informational" in risk or "info" in risk:
        return "Informational"

    risk_code = str(alert.get("riskcode", "")).strip()
    risk_code_map = {
        "0": "Informational",
        "1": "Low",
        "2": "Medium",
        "3": "High",
    }
    return risk_code_map.get(risk_code, "Unknown")


def main() -> int:
    args = parse_args()
    report_path = Path(args.report)

    try:
        report = load_report(report_path)
    except FileNotFoundError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as error:
        print(f"ERROR: Invalid JSON report: {error}", file=sys.stderr)
        return 1

    alerts = extract_alerts(report)
    counts = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
        "Unknown": 0,
    }

    for alert in alerts:
        counts[normalize_risk(alert)] += 1

    total_alerts = len(alerts)
    medium_or_higher = counts["Medium"] + counts["High"]

    print("OWASP ZAP report summary")
    print("========================")
    print(f"Report:        {report_path}")
    print(f"Total alerts:  {total_alerts}")
    print(f"High:          {counts['High']}")
    print(f"Medium:        {counts['Medium']}")
    print(f"Low:           {counts['Low']}")
    print(f"Info:          {counts['Informational']}")
    print(f"Unknown:       {counts['Unknown']}")

    if total_alerts < args.min_total_alerts:
        print(
            f"ERROR: Expected at least {args.min_total_alerts} total alerts, got {total_alerts}",
            file=sys.stderr,
        )
        return 1

    if medium_or_higher < args.min_medium_alerts:
        print(
            f"ERROR: Expected at least {args.min_medium_alerts} Medium+High alerts, "
            f"got {medium_or_higher}",
            file=sys.stderr,
        )
        return 1

    if counts["High"] < args.min_high_alerts:
        print(
            f"ERROR: Expected at least {args.min_high_alerts} High alerts, got {counts['High']}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
