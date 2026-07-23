from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "examples" / "fixtures"
sys.path.insert(0, str(REPO_ROOT / "src"))


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class FixtureTests(unittest.TestCase):
    def test_shipped_release_scenarios_have_expected_decisions(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = load("baseline.json")
        scenarios = (
            ("candidate-safe.json", "policy.json", "pass"),
            ("candidate-risky.json", "policy.json", "block"),
            ("candidate-exception.json", "policy-with-exception.json", "pass"),
        )

        for candidate_name, policy_name, expected in scenarios:
            with self.subTest(candidate=candidate_name):
                report = evaluate_release(
                    baseline,
                    load(candidate_name),
                    load(policy_name),
                    as_of="2026-07-23",
                )
                self.assertEqual(expected, report["decision"])


if __name__ == "__main__":
    unittest.main()
