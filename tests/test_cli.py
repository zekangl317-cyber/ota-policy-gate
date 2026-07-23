from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from test_policy import evidence_bundle, release_policy


class CliTests(unittest.TestCase):
    def test_pass_warn_and_block_have_distinct_documented_codes(self) -> None:
        from ota_policy_gate.cli import decision_exit_code

        self.assertEqual((0, 10, 20), tuple(decision_exit_code(item) for item in ("pass", "warn", "block")))

    def test_cli_writes_both_reports_and_returns_block_code(self) -> None:
        from ota_policy_gate.cli import BLOCK_EXIT, main

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["interfaces"] = []
        policy = release_policy()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_path = root / "baseline.json"
            candidate_path = root / "candidate.json"
            policy_path = root / "policy.json"
            json_path = root / "decision.json"
            markdown_path = root / "decision.md"
            for path, value in (
                (baseline_path, baseline),
                (candidate_path, candidate),
                (policy_path, policy),
            ):
                path.write_text(json.dumps(value), encoding="utf-8")

            code = main(
                [
                    "evaluate",
                    "--baseline",
                    str(baseline_path),
                    "--candidate",
                    str(candidate_path),
                    "--policy",
                    str(policy_path),
                    "--as-of",
                    "2026-07-23",
                    "--json-out",
                    str(json_path),
                    "--markdown-out",
                    str(markdown_path),
                    "--quiet",
                ]
            )

            self.assertEqual(BLOCK_EXIT, code)
            self.assertEqual("block", json.loads(json_path.read_text(encoding="utf-8"))["decision"])
            self.assertIn("`INTERFACE.REMOVED`", markdown_path.read_text(encoding="utf-8"))

    def test_release_name_mismatch_blocks_with_stable_reports(self) -> None:
        from ota_policy_gate.cli import BLOCK_EXIT, main

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["release"]["name"] = "unrelated-product"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_path = root / "baseline.json"
            candidate_path = root / "candidate.json"
            policy_path = root / "policy.json"
            json_path = root / "decision.json"
            markdown_path = root / "decision.md"
            for path, value in (
                (baseline_path, baseline),
                (candidate_path, candidate),
                (policy_path, release_policy()),
            ):
                path.write_text(json.dumps(value), encoding="utf-8")
            argv = [
                "evaluate",
                "--baseline",
                str(baseline_path),
                "--candidate",
                str(candidate_path),
                "--policy",
                str(policy_path),
                "--as-of",
                "2026-07-23",
                "--json-out",
                str(json_path),
                "--markdown-out",
                str(markdown_path),
            ]

            first_stdout = io.StringIO()
            with redirect_stdout(first_stdout):
                first_code = main(argv)
            first_json = json_path.read_text(encoding="utf-8")
            first_markdown = markdown_path.read_text(encoding="utf-8")

            second_stdout = io.StringIO()
            with redirect_stdout(second_stdout):
                second_code = main(argv)

            self.assertEqual((BLOCK_EXIT, BLOCK_EXIT), (first_code, second_code))
            self.assertEqual(first_stdout.getvalue(), second_stdout.getvalue())
            self.assertEqual(first_json, json_path.read_text(encoding="utf-8"))
            self.assertEqual(first_markdown, markdown_path.read_text(encoding="utf-8"))
            self.assertEqual(first_json, first_stdout.getvalue())

            report = json.loads(first_json)
            self.assertEqual(
                ("controller", "unrelated-product"),
                (
                    report["baseline_release"]["name"],
                    report["candidate_release"]["name"],
                ),
            )
            self.assertEqual(
                [
                    {
                        "rule_id": "RELEASE.NAME_MISMATCH",
                        "severity": "block",
                        "status": "active",
                        "subject": "release.name",
                        "message": (
                            "The candidate release name does not match the baseline "
                            "release name."
                        ),
                        "details": {
                            "baseline_release_name": "controller",
                            "candidate_release_name": "unrelated-product",
                        },
                    }
                ],
                report["findings"],
            )
            self.assertIn("- Baseline: `controller 1.0.0`", first_markdown)
            self.assertIn("- Candidate: `unrelated-product 1.0.0`", first_markdown)
            self.assertIn("`RELEASE.NAME_MISMATCH`", first_markdown)

    def test_malformed_json_returns_input_error_without_reports(self) -> None:
        from ota_policy_gate.cli import INPUT_ERROR_EXIT, main

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            malformed = root / "malformed.json"
            malformed.write_text("{not-json", encoding="utf-8")

            code = main(
                [
                    "evaluate",
                    "--baseline",
                    str(malformed),
                    "--candidate",
                    str(malformed),
                    "--policy",
                    str(malformed),
                    "--as-of",
                    "2026-07-23",
                    "--quiet",
                ]
            )

            self.assertEqual(INPUT_ERROR_EXIT, code)

    def test_duplicate_object_keys_return_input_error(self) -> None:
        from ota_policy_gate.cli import INPUT_ERROR_EXIT, main

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_path = root / "baseline.json"
            candidate_path = root / "candidate.json"
            policy_path = root / "policy.json"
            baseline_json = json.dumps(evidence_bundle()).replace(
                '"name": "controller"',
                '"name": "shadow-controller", "name": "controller"',
                1,
            )
            baseline_path.write_text(baseline_json, encoding="utf-8")
            candidate_path.write_text(
                json.dumps(evidence_bundle()), encoding="utf-8"
            )
            policy_path.write_text(json.dumps(release_policy()), encoding="utf-8")
            stderr = io.StringIO()

            with redirect_stderr(stderr):
                code = main(
                    [
                        "evaluate",
                        "--baseline",
                        str(baseline_path),
                        "--candidate",
                        str(candidate_path),
                        "--policy",
                        str(policy_path),
                        "--as-of",
                        "2026-07-23",
                        "--quiet",
                    ]
                )

            self.assertEqual(INPUT_ERROR_EXIT, code)
            self.assertIn("duplicate object key 'name'", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
