from __future__ import annotations

import json
import re
import sys
import unittest
from copy import deepcopy
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class ReportingTests(unittest.TestCase):
    def test_json_and_markdown_reports_are_deterministic(self) -> None:
        from ota_policy_gate import render_json, render_markdown

        report = {
            "schema_version": "ota-policy-report/v1",
            "decision": "warn",
            "evaluation_date": "2026-07-23",
            "baseline_release": {"name": "controller", "version": "1.0.0"},
            "candidate_release": {"name": "controller", "version": "1.1.0"},
            "policy_schema_version": "ota-policy/v1",
            "evidence_notice": "Caller supplied verification metadata.",
            "risk_usage": {"new_dependencies": 1},
            "risk_usage_before_exceptions": {"new_dependencies": 1},
            "findings": [
                {
                    "rule_id": "SBOM.DEPENDENCY_ADDED",
                    "severity": "warn",
                    "status": "active",
                    "subject": "pkg:pypi/example",
                    "message": "A dependency was added.",
                    "details": {"version": "1.0.0"},
                }
            ],
        }

        json_first = render_json(report)
        markdown_first = render_markdown(report)

        self.assertEqual(json_first, render_json(report))
        self.assertEqual(markdown_first, render_markdown(report))
        self.assertEqual(report, json.loads(json_first))
        self.assertIn("`SBOM.DEPENDENCY_ADDED`", markdown_first)
        self.assertTrue(json_first.endswith("\n"))
        self.assertTrue(markdown_first.endswith("\n"))

    def test_markdown_code_spans_survive_backticks_and_pipes(self) -> None:
        from ota_policy_gate import render_markdown

        report = {
            "decision": "warn",
            "evaluation_date": "2026-07-23",
            "baseline_release": {
                "name": "controller `inline`",
                "version": "1.0.0",
            },
            "candidate_release": {
                "name": "controller ``nested``|next-line",
                "version": "1.1.0",
            },
            "evidence_notice": "Caller supplied verification metadata.",
            "risk_usage": {"metric`|name": 1},
            "risk_usage_before_exceptions": {"metric`|name": 1},
            "findings": [
                {
                    "rule_id": "RULE`ID",
                    "severity": "warn",
                    "status": "active",
                    "exception_id": "ticket``|one-two",
                    "subject": "`subject|value`",
                    "message": "A fixed explanation.",
                }
            ],
        }

        rendered = render_markdown(report)
        self.assertIn("- Baseline: ``controller `inline` 1.0.0``", rendered)
        self.assertIn(
            "- Candidate: ```controller ``nested``\\|next-line 1.1.0```",
            rendered,
        )
        self.assertIn("``metric`\\|name``", rendered)
        self.assertIn("``RULE`ID``", rendered)
        self.assertIn("```active (ticket``\\|one-two)```", rendered)
        self.assertIn("`` `subject\\|value` ``", rendered)

    def test_markdown_rejects_controls_and_separators_in_hand_built_reports(self) -> None:
        from ota_policy_gate import EvidenceValidationError, render_markdown

        report_template = {
            "decision": "warn",
            "evaluation_date": "2026-07-23",
            "baseline_release": {"name": "controller", "version": "1.0.0"},
            "candidate_release": {"name": "controller", "version": "1.1.0"},
            "evidence_notice": "Caller supplied verification metadata.",
            "risk_usage": {"new_dependencies": 1},
            "risk_usage_before_exceptions": {"new_dependencies": 1},
            "findings": [
                {
                    "rule_id": "SBOM.DEPENDENCY_ADDED",
                    "severity": "warn",
                    "status": "active",
                    "subject": "pkg:pypi/example",
                    "message": "A dependency was added.",
                }
            ],
        }

        cases = (
            (("candidate_release", "name"), "controller\u202espoof", "U+202E"),
            (("evidence_notice",), "notice\x00hidden", "U+0000"),
            (("baseline_release", "name"), "controller\nnext", "U+000A"),
            (("candidate_release", "version"), "1.1\r0", "U+000D"),
            (("findings", 0, "subject"), "package\x1bhidden", "U+001B"),
            (("findings", 0, "message"), "first\u2028second", "U+2028"),
            (("findings", 0, "rule_id"), "RULE\u2029NEXT", "U+2029"),
        )
        for path, value, code_point in cases:
            with self.subTest(path=path, code_point=code_point):
                report = deepcopy(report_template)
                container = report
                for segment in path[:-1]:
                    container = container[segment]
                container[path[-1]] = value

                with self.assertRaisesRegex(
                    EvidenceValidationError, re.escape(code_point)
                ):
                    render_markdown(report)

    def test_json_rejects_invisible_or_noncharacter_report_text(self) -> None:
        from ota_policy_gate import EvidenceValidationError, render_json

        for value, code_point in (
            ("controller\u202espoof", "U+202E"),
            ("private\ue000label", "U+E000"),
            ("surrogate\ud800label", "U+D800"),
        ):
            with self.subTest(code_point=code_point):
                with self.assertRaisesRegex(
                    EvidenceValidationError,
                    re.escape(code_point),
                ):
                    render_json({"decision": "pass", "label": value})

    def test_markdown_preserves_valid_non_ascii_text(self) -> None:
        from ota_policy_gate import render_markdown

        report = {
            "decision": "pass",
            "evaluation_date": "2026-07-23",
            "baseline_release": {"name": "控制器 München", "version": "版本-β"},
            "candidate_release": {"name": "控制器 München", "version": "版本-γ"},
            "evidence_notice": "Vérification fournie par 审查员.",
            "risk_usage": {},
            "risk_usage_before_exceptions": {},
            "findings": [],
        }

        rendered = render_markdown(report)
        self.assertIn("`控制器 München 版本-β`", rendered)
        self.assertIn("Vérification fournie par 审查员.", rendered)


if __name__ == "__main__":
    unittest.main()
