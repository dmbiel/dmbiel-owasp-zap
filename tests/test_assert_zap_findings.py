import importlib.util
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "assert_zap_findings.py"
SPEC = importlib.util.spec_from_file_location("assert_zap_findings", MODULE_PATH)
assert SPEC is not None
assert SPEC.loader is not None
assert_zap_findings = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = assert_zap_findings
SPEC.loader.exec_module(assert_zap_findings)


class AssertZapFindingsTests(unittest.TestCase):
    def test_extracts_alerts_from_site_list_and_root_alerts(self) -> None:
        report = {
            "site": [
                {
                    "name": "juice-shop",
                    "alerts": [
                        {"riskdesc": "Medium (High)", "name": "Example"},
                        {"riskcode": "1", "name": "Low by code"},
                        "ignored",
                    ],
                }
            ],
            "alerts": [{"risk": "Informational", "name": "Root alert"}],
        }

        alerts = assert_zap_findings.extract_alerts(report)

        self.assertEqual(len(alerts), 3)

    def test_extracts_alerts_from_single_site_object(self) -> None:
        report = {
            "site": {
                "name": "juice-shop",
                "alerts": [{"riskcode": "3", "name": "High by code"}],
            }
        }

        alerts = assert_zap_findings.extract_alerts(report)

        self.assertEqual(alerts, [{"riskcode": "3", "name": "High by code"}])

    def test_normalizes_risk_text_and_codes(self) -> None:
        cases = [
            ({"riskdesc": "High (Medium)"}, "High"),
            ({"risk": "Medium"}, "Medium"),
            ({"risk": "Low"}, "Low"),
            ({"risk": "Informational"}, "Informational"),
            ({"riskcode": "0"}, "Informational"),
            ({"riskcode": "1"}, "Low"),
            ({"riskcode": "2"}, "Medium"),
            ({"riskcode": "3"}, "High"),
            ({}, "Unknown"),
        ]

        for alert, expected in cases:
            with self.subTest(alert=alert):
                self.assertEqual(assert_zap_findings.normalize_risk(alert), expected)

    def test_main_passes_when_thresholds_are_met(self) -> None:
        report = {
            "site": [
                {
                    "alerts": [
                        {"risk": "Medium"},
                        {"riskcode": "3"},
                        {"risk": "Low"},
                    ]
                }
            ]
        }

        result, stdout, stderr = self.run_main(report, "--min-total-alerts", "3", "--min-high-alerts", "1")

        self.assertEqual(result, 0)
        self.assertIn("Total alerts:  3", stdout)
        self.assertEqual(stderr, "")

    def test_main_fails_when_medium_threshold_is_not_met(self) -> None:
        report = {"alerts": [{"risk": "Low"}]}

        result, _, stderr = self.run_main(report, "--min-medium-alerts", "1")

        self.assertEqual(result, 1)
        self.assertIn("Expected at least 1 Medium+High alerts", stderr)

    def test_main_fails_for_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "zap.json"
            report_path.write_text("{not-json", encoding="utf-8")

            result, _, stderr = self.run_main_path(report_path)

        self.assertEqual(result, 1)
        self.assertIn("Invalid JSON report", stderr)

    def run_main(self, report: dict, *extra_args: str) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "zap.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            return self.run_main_path(report_path, *extra_args)

    def run_main_path(self, report_path: Path, *extra_args: str) -> tuple[int, str, str]:
        argv = ["assert_zap_findings.py", "--report", str(report_path), *extra_args]
        stdout = StringIO()
        stderr = StringIO()

        with patch.object(sys, "argv", argv):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = assert_zap_findings.main()

        return result, stdout.getvalue(), stderr.getvalue()


if __name__ == "__main__":
    unittest.main()
