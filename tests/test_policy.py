from __future__ import annotations

import re
import sys
import unittest
from copy import deepcopy
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

CONTRACT_HASH_V1 = "sha256:" + ("1" * 64)
CONTRACT_HASH_V2 = "sha256:" + ("2" * 64)


def evidence_bundle() -> dict:
    return {
        "schema_version": "ota-evidence/v1",
        "release": {"name": "controller", "version": "1.0.0"},
        "sbom": {
            "components": [
                {
                    "id": "pkg:pypi/safe-lib",
                    "name": "safe-lib",
                    "version": "1.0.0",
                    "licenses": ["MIT"],
                }
            ]
        },
        "signed_manifest": {
            "artifact_digest": "sha256:aaaaaaaaaaaaaaaa",
            "verification": {"status": "verified", "verifier": "fixture-verifier"},
        },
        "interfaces": [
            {
                "id": "telemetry.read",
                "version": "1.0.0",
                "contract_hash": CONTRACT_HASH_V1,
            }
        ],
        "authorities": [
            {"principal": "updater", "resource": "slot-b", "actions": ["install"]}
        ],
        "rollback": {
            "status": "pass",
            "procedure_id": "rollback-slot-v1",
            "evidence_uri": "file:rollback-report.json",
            "artifact_digest": "sha256:aaaaaaaaaaaaaaaa",
        },
    }


def release_policy() -> dict:
    return {
        "schema_version": "ota-policy/v1",
        "manifest": {"accepted_verification_statuses": ["verified"]},
        "rollback": {"required": True},
        "risk_budgets": {},
        "exceptions": [],
    }


class PolicyEvaluationTests(unittest.TestCase):
    def test_unchanged_release_with_verified_evidence_passes(self) -> None:
        from ota_policy_gate import evaluate_release

        bundle = evidence_bundle()
        policy = release_policy()

        report = evaluate_release(bundle, bundle, policy, as_of="2026-07-23")

        self.assertEqual("pass", report["decision"])

    def test_release_name_mismatch_emits_stable_blocking_finding(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["release"]["name"] = "unrelated-product"

        report = evaluate_release(
            baseline, candidate, release_policy(), as_of="2026-07-23"
        )

        self.assertEqual("block", report["decision"])
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

    def test_empty_release_is_rejected(self) -> None:
        from ota_policy_gate import EvidenceValidationError, evaluate_release

        candidate = evidence_bundle()
        candidate["release"] = {}

        with self.assertRaisesRegex(
            EvidenceValidationError, r"candidate\.release\.name must be a non-empty string"
        ):
            evaluate_release(
                evidence_bundle(), candidate, release_policy(), as_of="2026-07-23"
            )

    def test_release_name_and_version_must_be_strings(self) -> None:
        from ota_policy_gate import EvidenceValidationError, evaluate_release

        for field, value in (("name", True), ("version", 2)):
            with self.subTest(field=field, value=value):
                candidate = evidence_bundle()
                candidate["release"][field] = value

                with self.assertRaisesRegex(
                    EvidenceValidationError,
                    rf"candidate\.release\.{field} must be a non-empty string",
                ):
                    evaluate_release(
                        evidence_bundle(),
                        candidate,
                        release_policy(),
                        as_of="2026-07-23",
                    )

    def test_bidi_override_in_release_label_is_rejected(self) -> None:
        from ota_policy_gate import EvidenceValidationError, evaluate_release

        candidate = evidence_bundle()
        candidate["release"]["name"] = "controller\u202espoof"

        with self.assertRaisesRegex(
            EvidenceValidationError,
            r"candidate\.release\.name contains disallowed Unicode .* U\+202E",
        ):
            evaluate_release(
                evidence_bundle(), candidate, release_policy(), as_of="2026-07-23"
            )

    def test_controls_and_ambiguous_whitespace_are_rejected_across_text_fields(
        self,
    ) -> None:
        from ota_policy_gate import EvidenceValidationError, evaluate_release

        candidate_template = evidence_bundle()
        candidate_template["interfaces"][0]["compatible_with"] = [CONTRACT_HASH_V1]
        policy_template = release_policy()
        policy_template["allowed_licenses"] = ["MIT"]
        policy_template["rollback"]["required_fields"] = ["procedure_id"]
        policy_template["exceptions"] = [
            {
                "id": "EXC-UNICODE",
                "rule_ids": ["AUTHORITY.PRIVILEGE_EXPANSION"],
                "subjects": ["*"],
                "expires": "2026-08-01",
                "approved_by": "release-safety-board",
                "justification": "Regression fixture.",
            }
        ]
        cases = (
            ("candidate", ("release", "name"), "controller\u202espoof", "U+202E"),
            (
                "candidate",
                ("sbom", "components", 0, "name"),
                "safe\u2066-lib",
                "U+2066",
            ),
            (
                "candidate",
                ("sbom", "components", 0, "licenses", 0),
                "MI\u200bT",
                "U+200B",
            ),
            (
                "candidate",
                ("interfaces", 0, "compatible_with", 0),
                f"{CONTRACT_HASH_V1}\u2028continuation",
                "U+2028",
            ),
            (
                "candidate",
                ("authorities", 0, "principal"),
                "updater\tadmin",
                "U+0009",
            ),
            (
                "candidate",
                ("authorities", 0, "actions", 0),
                "install\nactivate",
                "U+000A",
            ),
            (
                "candidate",
                ("signed_manifest", "verification", "verifier"),
                "verifier\u2029next",
                "U+2029",
            ),
            (
                "candidate",
                ("rollback", "evidence_uri"),
                "file:rollback\u00a0report.json",
                "U+00A0",
            ),
            (
                "policy",
                ("exceptions", 0, "id"),
                "EXC\u202e-SPOOF",
                "U+202E",
            ),
            (
                "policy",
                ("exceptions", 0, "approved_by"),
                "board\u2067member",
                "U+2067",
            ),
            (
                "policy",
                ("exceptions", 0, "justification"),
                "line\u0085next",
                "U+0085",
            ),
            (
                "policy",
                ("exceptions", 0, "rule_ids", 0),
                "AUTHORITY.\u2028PRIVILEGE_EXPANSION",
                "U+2028",
            ),
            (
                "policy",
                ("exceptions", 0, "subjects", 0),
                "updater\u2029slot-b",
                "U+2029",
            ),
        )
        for owner, path, value, code_point in cases:
            with self.subTest(owner=owner, path=path, code_point=code_point):
                candidate = deepcopy(candidate_template)
                policy = deepcopy(policy_template)
                container = candidate if owner == "candidate" else policy
                for segment in path[:-1]:
                    container = container[segment]
                container[path[-1]] = value

                with self.assertRaisesRegex(
                    EvidenceValidationError,
                    rf"{re.escape(code_point)}",
                ):
                    evaluate_release(
                        evidence_bundle(),
                        candidate,
                        policy,
                        as_of="2026-07-23",
                    )

    def test_legitimate_unicode_letters_are_preserved(self) -> None:
        from ota_policy_gate import evaluate_release, render_markdown

        baseline = evidence_bundle()
        baseline["release"] = {"name": "控制器 München", "version": "版本-β"}
        baseline["sbom"]["components"][0] = {
            "id": "pkg:generic/安全库",
            "purl": "pkg:generic/安全库",
            "name": "安全库 Δέλτα",
            "version": "版本-一",
            "licenses": ["自定义-许可证"],
        }
        baseline["interfaces"][0]["id"] = "遥测.读取"
        baseline["interfaces"][0]["version"] = "版本-一"
        baseline["authorities"][0] = {
            "principal": "更新者",
            "resource": "槽位-β",
            "actions": ["安装"],
        }
        baseline["signed_manifest"]["verification"] = {
            "status": "已验证",
            "verifier": "审查员 Αλφα",
            "identity": "签名者-甲",
        }
        baseline["rollback"]["procedure_id"] = "回滚-流程-一"
        baseline["rollback"]["evidence_uri"] = "file:回滚报告.json"
        candidate = deepcopy(baseline)
        policy = release_policy()
        policy["allowed_licenses"] = ["自定义-许可证"]
        policy["manifest"]["accepted_verification_statuses"] = ["已验证"]
        policy["exceptions"] = [
            {
                "id": "例外-一",
                "rule_ids": ["不存在.规则"],
                "subjects": ["主题-甲"],
                "expires": "2026-08-01",
                "approved_by": "安全委员会",
                "justification": "已审核变更。",
            }
        ]

        report = evaluate_release(baseline, candidate, policy, as_of="2026-07-23")
        markdown = render_markdown(report)

        self.assertEqual("pass", report["decision"])
        self.assertEqual("控制器 München", report["baseline_release"]["name"])
        self.assertIn("`控制器 München 版本-β`", markdown)

    def test_versioned_top_level_records_reject_unknown_fields(self) -> None:
        from ota_policy_gate import EvidenceValidationError, evaluate_release

        cases = (
            ("candidate", {"unexpected": True}, release_policy()),
            ("policy", {}, {**release_policy(), "unexpected": True}),
        )
        for label, candidate_updates, policy in cases:
            with self.subTest(record=label):
                candidate = evidence_bundle()
                candidate.update(candidate_updates)

                with self.assertRaisesRegex(
                    EvidenceValidationError,
                    rf"{label} contains unknown field 'unexpected'",
                ):
                    evaluate_release(
                        evidence_bundle(), candidate, policy, as_of="2026-07-23"
                    )

    def test_evidence_nested_records_reject_unknown_fields(self) -> None:
        from ota_policy_gate import EvidenceValidationError, evaluate_release

        cases = (
            (("release",), "candidate.release"),
            (("sbom",), "candidate.sbom"),
            (("sbom", "components", 0), "candidate.sbom.components[0]"),
            (("interfaces", 0), "candidate.interfaces[0]"),
            (("authorities", 0), "candidate.authorities[0]"),
            (("signed_manifest",), "candidate.signed_manifest"),
            (
                ("signed_manifest", "verification"),
                "candidate.signed_manifest.verification",
            ),
            (("rollback",), "candidate.rollback"),
        )
        for path, label in cases:
            with self.subTest(record=label):
                candidate = evidence_bundle()
                record = candidate
                for segment in path:
                    record = record[segment]
                record["unexpected"] = True

                with self.assertRaisesRegex(
                    EvidenceValidationError,
                    rf"{re.escape(label)} contains unknown field 'unexpected'",
                ):
                    evaluate_release(
                        evidence_bundle(),
                        candidate,
                        release_policy(),
                        as_of="2026-07-23",
                    )

    def test_policy_nested_records_reject_unknown_fields(self) -> None:
        from ota_policy_gate import EvidenceValidationError, evaluate_release

        exception = {
            "id": "EXC-STRICT-SCHEMA",
            "rule_ids": ["AUTHORITY.PRIVILEGE_EXPANSION"],
            "subjects": ["*"],
            "expires": "2026-08-01",
            "approved_by": "release-safety-board",
            "justification": "Regression fixture.",
        }
        cases = (
            (("manifest",), "policy.manifest", None),
            (("rollback",), "policy.rollback", None),
            (("risk_budgets",), "policy.risk_budgets", None),
            (("exceptions", 0), "policy.exceptions[0]", exception),
        )
        for path, label, exception_record in cases:
            with self.subTest(record=label):
                policy = release_policy()
                if exception_record is not None:
                    policy["exceptions"] = [deepcopy(exception_record)]
                record = policy
                for segment in path:
                    record = record[segment]
                record["unexpected"] = True

                with self.assertRaisesRegex(
                    EvidenceValidationError,
                    rf"{re.escape(label)} contains unknown field 'unexpected'",
                ):
                    evaluate_release(
                        evidence_bundle(),
                        evidence_bundle(),
                        policy,
                        as_of="2026-07-23",
                    )

    def test_evidence_scalar_fields_do_not_coerce_wrong_types(self) -> None:
        from ota_policy_gate import EvidenceValidationError, evaluate_release

        cases = (
            (
                ("sbom", "components", 0, "version"),
                True,
                "candidate.sbom.components[0].version",
            ),
            (
                ("sbom", "components", 0, "licenses", 0),
                False,
                "candidate.sbom.components[0].licenses[0]",
            ),
            (("interfaces", 0, "id"), 7, "candidate.interfaces[0].id"),
            (
                ("interfaces", 0, "contract_hash"),
                False,
                "candidate.interfaces[0].contract_hash",
            ),
            (
                ("interfaces", 0, "compatible_with"),
                [True],
                "candidate.interfaces[0].compatible_with[0]",
            ),
            (
                ("authorities", 0, "principal"),
                False,
                "candidate.authorities[0].principal",
            ),
            (
                ("authorities", 0, "actions", 0),
                True,
                "candidate.authorities[0].actions[0]",
            ),
            (
                ("signed_manifest", "artifact_digest"),
                True,
                "candidate.signed_manifest.artifact_digest",
            ),
            (
                ("signed_manifest", "verification", "status"),
                1,
                "candidate.signed_manifest.verification.status",
            ),
            (("rollback", "status"), False, "candidate.rollback.status"),
        )
        for path, value, label in cases:
            with self.subTest(field=label):
                candidate = evidence_bundle()
                container = candidate
                for segment in path[:-1]:
                    container = container[segment]
                container[path[-1]] = value

                with self.assertRaisesRegex(
                    EvidenceValidationError,
                    rf"{re.escape(label)} must be (?:a non-empty|a) string",
                ):
                    evaluate_release(
                        evidence_bundle(),
                        candidate,
                        release_policy(),
                        as_of="2026-07-23",
                    )

    def test_policy_scalar_fields_do_not_coerce_wrong_types(self) -> None:
        from ota_policy_gate import EvidenceValidationError, evaluate_release

        policy_template = release_policy()
        policy_template["allowed_licenses"] = ["MIT"]
        policy_template["manifest"]["require_artifact_digest"] = True
        policy_template["rollback"]["required_fields"] = [
            "procedure_id",
            "evidence_uri",
            "artifact_digest",
        ]
        policy_template["risk_budgets"] = {"new_dependencies": 0}
        policy_template["exceptions"] = [
            {
                "id": "EXC-TYPED",
                "rule_ids": ["AUTHORITY.PRIVILEGE_EXPANSION"],
                "subjects": ["*"],
                "expires": "2026-08-01",
                "approved_by": "release-safety-board",
                "justification": "Regression fixture.",
            }
        ]
        cases = (
            (
                ("allowed_licenses", 0),
                True,
                r"policy\.allowed_licenses\[0\] must be a string",
            ),
            (
                ("manifest", "accepted_verification_statuses", 0),
                1,
                r"policy\.manifest\.accepted_verification_statuses\[0\] "
                r"must be a string",
            ),
            (
                ("manifest", "require_artifact_digest"),
                "true",
                r"policy\.manifest\.require_artifact_digest must be a boolean",
            ),
            (
                ("rollback", "required"),
                1,
                r"policy\.rollback\.required must be a boolean",
            ),
            (
                ("rollback", "required_fields", 0),
                False,
                r"policy\.rollback\.required_fields\[0\] must be a string",
            ),
            (
                ("risk_budgets", "new_dependencies"),
                True,
                r"policy\.risk_budgets\.new_dependencies must be a non-negative integer",
            ),
            (
                ("exceptions", 0, "id"),
                True,
                r"policy\.exceptions\[0\]\.id must be a non-empty string",
            ),
            (
                ("exceptions", 0, "rule_ids", 0),
                7,
                r"policy\.exceptions\[0\]\.rule_ids\[0\] must be a string",
            ),
            (
                ("exceptions", 0, "subjects", 0),
                False,
                r"policy\.exceptions\[0\]\.subjects\[0\] must be a string",
            ),
        )
        for path, value, message_pattern in cases:
            with self.subTest(path=path):
                policy = deepcopy(policy_template)
                container = policy
                for segment in path[:-1]:
                    container = container[segment]
                container[path[-1]] = value

                with self.assertRaisesRegex(
                    EvidenceValidationError, message_pattern
                ):
                    evaluate_release(
                        evidence_bundle(),
                        evidence_bundle(),
                        policy,
                        as_of="2026-07-23",
                    )

    def test_dependency_and_license_drift_are_explained_and_budgeted(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["release"]["version"] = "1.1.0"
        candidate["sbom"]["components"][0]["version"] = "2.0.0"
        candidate["sbom"]["components"][0]["licenses"] = ["GPL-3.0-only"]
        policy = release_policy()
        policy["allowed_licenses"] = ["MIT", "Apache-2.0"]
        policy["risk_budgets"] = {"changed_dependencies": 0, "license_changes": 0}

        report = evaluate_release(baseline, candidate, policy, as_of="2026-07-23")

        rule_ids = {finding["rule_id"] for finding in report["findings"]}
        self.assertEqual("block", report["decision"])
        self.assertTrue(
            {
                "SBOM.DEPENDENCY_CHANGED",
                "SBOM.LICENSE_CHANGED",
                "SBOM.LICENSE_NOT_ALLOWED",
                "RISK_BUDGET.CHANGED_DEPENDENCIES_EXCEEDED",
                "RISK_BUDGET.LICENSE_CHANGES_EXCEEDED",
            }.issubset(rule_ids)
        )

    def test_removed_interface_blocks_release(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["interfaces"] = []
        policy = release_policy()
        policy["risk_budgets"] = {"removed_interfaces": 0}

        report = evaluate_release(baseline, candidate, policy, as_of="2026-07-23")

        active = {(item["rule_id"], item["subject"]) for item in report["findings"]}
        self.assertEqual("block", report["decision"])
        self.assertIn(("INTERFACE.REMOVED", "telemetry.read"), active)
        self.assertIn(
            ("RISK_BUDGET.REMOVED_INTERFACES_EXCEEDED", "removed_interfaces"), active
        )

    def test_privilege_expansion_blocks_release(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["authorities"][0]["actions"].append("activate")
        policy = release_policy()
        policy["risk_budgets"] = {"privilege_expansions": 0}

        report = evaluate_release(baseline, candidate, policy, as_of="2026-07-23")

        rules = {(item["rule_id"], item["subject"]) for item in report["findings"]}
        self.assertEqual("block", report["decision"])
        self.assertIn(
            ("AUTHORITY.PRIVILEGE_EXPANSION", "updater|slot-b|activate"), rules
        )
        self.assertIn(
            ("RISK_BUDGET.PRIVILEGE_EXPANSIONS_EXCEEDED", "privilege_expansions"),
            rules,
        )

    def test_failed_rollback_evidence_blocks_release(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["rollback"]["status"] = "fail"

        report = evaluate_release(
            baseline, candidate, release_policy(), as_of="2026-07-23"
        )

        self.assertEqual("block", report["decision"])
        self.assertIn(
            "ROLLBACK.TEST_FAILED",
            {item["rule_id"] for item in report["findings"]},
        )

    def test_approved_unexpired_exception_waives_matching_delta(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["authorities"][0]["actions"].append("activate")
        policy = release_policy()
        policy["risk_budgets"] = {"privilege_expansions": 0}
        policy["exceptions"] = [
            {
                "id": "EXC-2026-0042",
                "rule_ids": ["AUTHORITY.PRIVILEGE_EXPANSION"],
                "subjects": ["updater|slot-b|activate"],
                "expires": "2026-08-01",
                "approved_by": "release-safety-board",
                "justification": "Time-bounded commissioning authority.",
            }
        ]

        report = evaluate_release(baseline, candidate, policy, as_of="2026-07-23")

        expansion = next(
            item
            for item in report["findings"]
            if item["rule_id"] == "AUTHORITY.PRIVILEGE_EXPANSION"
        )
        self.assertEqual("pass", report["decision"])
        self.assertEqual("excepted", expansion["status"])
        self.assertEqual("EXC-2026-0042", expansion["exception_id"])
        self.assertEqual(0, report["risk_usage"]["privilege_expansions"])

    def test_approved_exception_releases_contraction_from_zero_budget(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["authorities"][0]["actions"] = []
        policy = release_policy()
        policy["risk_budgets"] = {"privilege_contractions": 0}
        policy["exceptions"] = [
            {
                "id": "EXC-CONTRACTION-1",
                "rule_ids": ["AUTHORITY.PRIVILEGE_CONTRACTION"],
                "subjects": ["updater|slot-b|install"],
                "expires": "2026-08-01",
                "approved_by": "release-safety-board",
                "justification": "Approved least-privilege reduction.",
            }
        ]

        report = evaluate_release(baseline, candidate, policy, as_of="2026-07-23")

        contraction = next(
            item
            for item in report["findings"]
            if item["rule_id"] == "AUTHORITY.PRIVILEGE_CONTRACTION"
        )
        self.assertEqual("pass", report["decision"])
        self.assertEqual("excepted", contraction["status"])
        self.assertEqual("EXC-CONTRACTION-1", contraction["exception_id"])
        self.assertEqual(
            1, report["risk_usage_before_exceptions"]["privilege_contractions"]
        )
        self.assertEqual(0, report["risk_usage"]["privilege_contractions"])
        self.assertNotIn(
            "RISK_BUDGET.PRIVILEGE_CONTRACTIONS_EXCEEDED",
            {item["rule_id"] for item in report["findings"]},
        )

    def test_approved_exception_releases_multiple_contraction_deltas(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        baseline["authorities"][0]["actions"].extend(["activate", "reboot"])
        candidate = deepcopy(baseline)
        candidate["authorities"][0]["actions"] = []
        subjects = {
            "updater|slot-b|activate",
            "updater|slot-b|install",
            "updater|slot-b|reboot",
        }
        policy = release_policy()
        policy["risk_budgets"] = {"privilege_contractions": 0}
        policy["exceptions"] = [
            {
                "id": "EXC-CONTRACTION-MULTI",
                "rule_ids": ["AUTHORITY.PRIVILEGE_CONTRACTION"],
                "subjects": sorted(subjects),
                "expires": "2026-08-01",
                "approved_by": "release-safety-board",
                "justification": "Approved least-privilege reductions.",
            }
        ]

        report = evaluate_release(baseline, candidate, policy, as_of="2026-07-23")

        contractions = [
            item
            for item in report["findings"]
            if item["rule_id"] == "AUTHORITY.PRIVILEGE_CONTRACTION"
        ]
        self.assertEqual("pass", report["decision"])
        self.assertEqual(subjects, {item["subject"] for item in contractions})
        self.assertEqual({"excepted"}, {item["status"] for item in contractions})
        self.assertEqual(
            {"EXC-CONTRACTION-MULTI"},
            {item["exception_id"] for item in contractions},
        )
        self.assertEqual(
            3, report["risk_usage_before_exceptions"]["privilege_contractions"]
        )
        self.assertEqual(0, report["risk_usage"]["privilege_contractions"])
        self.assertNotIn(
            "RISK_BUDGET.PRIVILEGE_CONTRACTIONS_EXCEEDED",
            {item["rule_id"] for item in report["findings"]},
        )

    def test_expired_exception_does_not_waive_finding(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["authorities"][0]["actions"].append("activate")
        policy = release_policy()
        policy["exceptions"] = [
            {
                "id": "EXC-EXPIRED",
                "rule_ids": ["AUTHORITY.PRIVILEGE_EXPANSION"],
                "subjects": ["updater|slot-b|activate"],
                "expires": "2026-07-22",
                "approved_by": "release-safety-board",
                "justification": "Commissioning window is over.",
            }
        ]

        report = evaluate_release(baseline, candidate, policy, as_of="2026-07-23")

        statuses = {
            (item["rule_id"], item["subject"]): item["status"]
            for item in report["findings"]
        }
        self.assertEqual("block", report["decision"])
        self.assertEqual(
            "active",
            statuses[("AUTHORITY.PRIVILEGE_EXPANSION", "updater|slot-b|activate")],
        )
        self.assertIn(("EXCEPTION.EXPIRED", "EXC-EXPIRED"), statuses)

    def test_rejected_supplied_verification_status_blocks_release(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["signed_manifest"]["verification"]["status"] = "failed"

        report = evaluate_release(
            baseline, candidate, release_policy(), as_of="2026-07-23"
        )

        self.assertEqual("block", report["decision"])
        self.assertIn(
            "MANIFEST.VERIFICATION_STATUS_REJECTED",
            {item["rule_id"] for item in report["findings"]},
        )
        self.assertIn("does not perform", report["evidence_notice"])

    def test_changed_contract_requires_explicit_compatibility_evidence(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["interfaces"][0]["version"] = "2.0.0"
        candidate["interfaces"][0]["contract_hash"] = CONTRACT_HASH_V2

        report = evaluate_release(
            baseline, candidate, release_policy(), as_of="2026-07-23"
        )

        self.assertEqual("block", report["decision"])
        self.assertIn(
            ("INTERFACE.INCOMPATIBLE", "telemetry.read"),
            {(item["rule_id"], item["subject"]) for item in report["findings"]},
        )

    def test_contract_hash_omission_emits_blocking_missing_evidence_finding(
        self,
    ) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        del candidate["interfaces"][0]["contract_hash"]

        report = evaluate_release(
            baseline, candidate, release_policy(), as_of="2026-07-23"
        )

        finding = next(
            item
            for item in report["findings"]
            if item["rule_id"] == "INTERFACE.MISSING_CONTRACT_EVIDENCE"
        )
        self.assertEqual("block", report["decision"])
        self.assertEqual("block", finding["severity"])
        self.assertEqual("active", finding["status"])
        self.assertEqual("telemetry.read", finding["subject"])
        self.assertEqual(
            baseline["interfaces"][0]["contract_hash"],
            finding["details"]["baseline_contract_hash"],
        )
        self.assertEqual(1, report["risk_usage"]["incompatible_interfaces"])

    def test_empty_contract_hash_cannot_downgrade_baseline_evidence(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["interfaces"][0]["contract_hash"] = ""
        candidate["interfaces"][0]["compatible_with"] = [
            baseline["interfaces"][0]["contract_hash"]
        ]

        report = evaluate_release(
            baseline, candidate, release_policy(), as_of="2026-07-23"
        )

        finding = next(
            item
            for item in report["findings"]
            if item["rule_id"] == "INTERFACE.MISSING_CONTRACT_EVIDENCE"
        )
        self.assertEqual("block", report["decision"])
        self.assertEqual("block", finding["severity"])
        self.assertEqual("telemetry.read", finding["subject"])
        self.assertEqual(1, report["risk_usage"]["incompatible_interfaces"])

    def test_invalid_contract_hash_is_missing_contract_evidence(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["interfaces"][0]["contract_hash"] = "sha256:not-a-digest"
        candidate["interfaces"][0]["compatible_with"] = [CONTRACT_HASH_V1]

        report = evaluate_release(
            baseline, candidate, release_policy(), as_of="2026-07-23"
        )

        finding = next(
            item
            for item in report["findings"]
            if item["rule_id"] == "INTERFACE.MISSING_CONTRACT_EVIDENCE"
        )
        self.assertEqual("block", report["decision"])
        self.assertEqual("invalid_contract_hash", finding["details"]["reason"])
        self.assertEqual(
            "sha256:not-a-digest",
            finding["details"]["candidate_contract_hash"],
        )
        self.assertEqual(1, report["risk_usage"]["incompatible_interfaces"])

    def test_invalid_baseline_contract_hash_is_rejected(self) -> None:
        from ota_policy_gate import EvidenceValidationError, evaluate_release

        baseline = evidence_bundle()
        baseline["interfaces"][0]["contract_hash"] = "sha256:not-a-digest"

        with self.assertRaisesRegex(
            EvidenceValidationError,
            r"baseline\.interfaces\[0\]\.contract_hash must be "
            r"'sha256:' followed by 64 lowercase hexadecimal characters",
        ):
            evaluate_release(
                baseline,
                evidence_bundle(),
                release_policy(),
                as_of="2026-07-23",
            )

    def test_hash_algorithm_downgrade_is_missing_contract_evidence(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["interfaces"][0]["contract_hash"] = "sha1:" + ("3" * 40)
        candidate["interfaces"][0]["compatible_with"] = [CONTRACT_HASH_V1]

        report = evaluate_release(
            baseline, candidate, release_policy(), as_of="2026-07-23"
        )

        finding = next(
            item
            for item in report["findings"]
            if item["rule_id"] == "INTERFACE.MISSING_CONTRACT_EVIDENCE"
        )
        self.assertEqual("block", report["decision"])
        self.assertEqual("invalid_contract_hash", finding["details"]["reason"])

    def test_changed_contract_accepts_explicit_baseline_compatibility(self) -> None:
        from ota_policy_gate import evaluate_release

        for compatibility_evidence in (CONTRACT_HASH_V1, "1.0.0"):
            with self.subTest(compatible_with=compatibility_evidence):
                baseline = evidence_bundle()
                candidate = deepcopy(baseline)
                candidate["interfaces"][0]["version"] = "2.0.0"
                candidate["interfaces"][0]["contract_hash"] = CONTRACT_HASH_V2
                candidate["interfaces"][0]["compatible_with"] = [
                    compatibility_evidence
                ]

                report = evaluate_release(
                    baseline,
                    candidate,
                    release_policy(),
                    as_of="2026-07-23",
                )

                self.assertEqual("pass", report["decision"])
                self.assertEqual(
                    0, report["risk_usage"]["incompatible_interfaces"]
                )

    def test_changed_contract_rejects_unrelated_compatibility_evidence(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["interfaces"][0]["version"] = "2.0.0"
        candidate["interfaces"][0]["contract_hash"] = CONTRACT_HASH_V2
        candidate["interfaces"][0]["compatible_with"] = [
            "sha256:" + ("3" * 64),
            "2.0.0",
        ]

        report = evaluate_release(
            baseline, candidate, release_policy(), as_of="2026-07-23"
        )

        self.assertEqual("block", report["decision"])
        self.assertIn(
            ("INTERFACE.INCOMPATIBLE", "telemetry.read"),
            {(item["rule_id"], item["subject"]) for item in report["findings"]},
        )
        self.assertEqual(1, report["risk_usage"]["incompatible_interfaces"])

    def test_empty_compatibility_entry_cannot_waive_contract_change(self) -> None:
        from ota_policy_gate import EvidenceValidationError, evaluate_release

        baseline = evidence_bundle()
        del baseline["interfaces"][0]["version"]
        candidate = deepcopy(baseline)
        candidate["interfaces"][0]["contract_hash"] = CONTRACT_HASH_V2
        candidate["interfaces"][0]["compatible_with"] = [""]

        with self.assertRaisesRegex(
            EvidenceValidationError,
            r"candidate\.interfaces\[0\]\.compatible_with\[0\] "
            r"must be a non-empty string",
        ):
            evaluate_release(
                baseline, candidate, release_policy(), as_of="2026-07-23"
            )

    def test_new_dependency_within_budget_warns(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["sbom"]["components"].append(
            {
                "id": "pkg:pypi/telemetry-codec",
                "name": "telemetry-codec",
                "version": "1.2.0",
                "licenses": ["Apache-2.0"],
            }
        )
        policy = release_policy()
        policy["allowed_licenses"] = ["MIT", "Apache-2.0"]
        policy["risk_budgets"] = {"new_dependencies": 1}

        report = evaluate_release(baseline, candidate, policy, as_of="2026-07-23")

        self.assertEqual("warn", report["decision"])
        self.assertEqual(1, report["risk_usage"]["new_dependencies"])
        self.assertIn(
            ("SBOM.DEPENDENCY_ADDED", "pkg:pypi/telemetry-codec"),
            {(item["rule_id"], item["subject"]) for item in report["findings"]},
        )

    def test_duplicate_component_identity_is_rejected(self) -> None:
        from ota_policy_gate import EvidenceValidationError, evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["sbom"]["components"].append(
            deepcopy(candidate["sbom"]["components"][0])
        )

        with self.assertRaisesRegex(EvidenceValidationError, "duplicate SBOM component"):
            evaluate_release(baseline, candidate, release_policy(), as_of="2026-07-23")

    def test_component_identity_falls_back_after_whitespace_only_fields(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        for bundle in (baseline, candidate):
            component = bundle["sbom"]["components"][0]
            component["id"] = "   "
            component["purl"] = "pkg:pypi/safe-lib"

        report = evaluate_release(
            baseline, candidate, release_policy(), as_of="2026-07-23"
        )

        self.assertEqual("pass", report["decision"])

    def test_active_license_allow_list_blocks_missing_component_evidence(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        baseline["sbom"]["components"][0]["licenses"] = []
        candidate["sbom"]["components"][0]["licenses"] = []
        policy = release_policy()
        policy["allowed_licenses"] = ["MIT"]

        report = evaluate_release(
            baseline, candidate, policy, as_of="2026-07-23"
        )

        self.assertEqual("block", report["decision"])
        self.assertIn(
            ("SBOM.LICENSE_EVIDENCE_MISSING", "pkg:pypi/safe-lib"),
            {(item["rule_id"], item["subject"]) for item in report["findings"]},
        )

    def test_rollback_evidence_must_be_complete_and_bound_to_artifact(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        del candidate["rollback"]["evidence_uri"]
        candidate["rollback"]["artifact_digest"] = "sha256:different"

        report = evaluate_release(
            baseline, candidate, release_policy(), as_of="2026-07-23"
        )

        rule_ids = {item["rule_id"] for item in report["findings"]}
        self.assertEqual("block", report["decision"])
        self.assertIn("ROLLBACK.EVIDENCE_INCOMPLETE", rule_ids)
        self.assertIn("ROLLBACK.ARTIFACT_DIGEST_MISMATCH", rule_ids)

    def test_manifest_metadata_requires_artifact_digest(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["signed_manifest"]["artifact_digest"] = ""

        report = evaluate_release(
            baseline, candidate, release_policy(), as_of="2026-07-23"
        )

        self.assertEqual("block", report["decision"])
        self.assertIn(
            "MANIFEST.ARTIFACT_DIGEST_MISSING",
            {item["rule_id"] for item in report["findings"]},
        )

    def test_authority_contraction_is_reported_without_blocking(self) -> None:
        from ota_policy_gate import evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["authorities"][0]["actions"] = []

        report = evaluate_release(
            baseline, candidate, release_policy(), as_of="2026-07-23"
        )

        self.assertEqual("pass", report["decision"])
        self.assertIn(
            ("AUTHORITY.PRIVILEGE_CONTRACTION", "updater|slot-b|install"),
            {(item["rule_id"], item["subject"]) for item in report["findings"]},
        )

    def test_malformed_nested_evidence_record_is_rejected(self) -> None:
        from ota_policy_gate import EvidenceValidationError, evaluate_release

        baseline = evidence_bundle()
        candidate = deepcopy(baseline)
        candidate["interfaces"] = ["not-an-interface-object"]

        with self.assertRaisesRegex(EvidenceValidationError, r"candidate.interfaces\[0\]"):
            evaluate_release(baseline, candidate, release_policy(), as_of="2026-07-23")


if __name__ == "__main__":
    unittest.main()
