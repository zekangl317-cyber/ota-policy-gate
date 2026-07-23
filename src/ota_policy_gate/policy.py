"""Policy evaluation over caller-supplied release evidence."""

from __future__ import annotations

from copy import deepcopy
from datetime import date
import re
from typing import Any, Mapping

from .validation import EvidenceValidationError, validate_human_readable_text


_EVIDENCE_KEYS = frozenset(
    {
        "schema_version",
        "release",
        "sbom",
        "signed_manifest",
        "interfaces",
        "authorities",
        "rollback",
    }
)
_POLICY_KEYS = frozenset(
    {
        "schema_version",
        "manifest",
        "allowed_licenses",
        "rollback",
        "risk_budgets",
        "exceptions",
    }
)
_RELEASE_KEYS = frozenset({"name", "version"})
_SBOM_KEYS = frozenset({"components"})
_COMPONENT_KEYS = frozenset({"id", "purl", "name", "version", "licenses"})
_INTERFACE_KEYS = frozenset({"id", "version", "contract_hash", "compatible_with"})
_CONTRACT_HASH_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_AUTHORITY_KEYS = frozenset({"principal", "resource", "actions"})
_SIGNED_MANIFEST_KEYS = frozenset({"artifact_digest", "verification"})
_VERIFICATION_KEYS = frozenset({"status", "verifier", "identity"})
_EVIDENCE_ROLLBACK_KEYS = frozenset(
    {"status", "procedure_id", "evidence_uri", "artifact_digest"}
)
_POLICY_MANIFEST_KEYS = frozenset(
    {"accepted_verification_statuses", "require_artifact_digest"}
)
_POLICY_ROLLBACK_KEYS = frozenset({"required", "required_fields"})
_RISK_BUDGET_KEYS = frozenset(
    {
        "new_dependencies",
        "removed_dependencies",
        "changed_dependencies",
        "license_changes",
        "removed_interfaces",
        "incompatible_interfaces",
        "privilege_expansions",
        "privilege_contractions",
        "rollback_failures",
        "manifest_verification_failures",
    }
)
_EXCEPTION_KEYS = frozenset(
    {"id", "rule_ids", "subjects", "expires", "approved_by", "justification"}
)


def _reject_unknown_keys(
    record: Mapping[str, Any], allowed: frozenset[str], label: str
) -> None:
    unknown = sorted((key for key in record if key not in allowed), key=repr)
    if unknown:
        raise EvidenceValidationError(f"{label} contains unknown field {unknown[0]!r}")


def _require_list(container: Mapping[str, Any], key: str, label: str) -> list[Any]:
    value = container.get(key, [])
    if not isinstance(value, list):
        raise EvidenceValidationError(f"{label}.{key} must be an array")
    return value


def _require_non_empty_string(
    container: Mapping[str, Any], key: str, label: str
) -> str:
    value = container.get(key)
    if not isinstance(value, str):
        raise EvidenceValidationError(f"{label}.{key} must be a non-empty string")
    validate_human_readable_text(value, f"{label}.{key}")
    if not value.strip():
        raise EvidenceValidationError(f"{label}.{key} must be a non-empty string")
    return value


def _validate_optional_string(
    container: Mapping[str, Any], key: str, label: str
) -> None:
    if key in container and not isinstance(container[key], str):
        raise EvidenceValidationError(f"{label}.{key} must be a string")
    if key in container:
        validate_human_readable_text(container[key], f"{label}.{key}")


def _validate_optional_bool(
    container: Mapping[str, Any], key: str, label: str
) -> None:
    if key in container and not isinstance(container[key], bool):
        raise EvidenceValidationError(f"{label}.{key} must be a boolean")


def _require_string_list(
    container: Mapping[str, Any], key: str, label: str
) -> list[Any]:
    values = _require_list(container, key, label)
    for index, value in enumerate(values):
        if not isinstance(value, str):
            raise EvidenceValidationError(
                f"{label}.{key}[{index}] must be a string"
            )
        validate_human_readable_text(value, f"{label}.{key}[{index}]")
    return values


def _require_non_empty_string_list(
    container: Mapping[str, Any], key: str, label: str
) -> list[Any]:
    values = _require_string_list(container, key, label)
    for index, value in enumerate(values):
        if not value.strip():
            raise EvidenceValidationError(
                f"{label}.{key}[{index}] must be a non-empty string"
            )
    return values


def _is_canonical_contract_hash(value: str) -> bool:
    return _CONTRACT_HASH_PATTERN.fullmatch(value) is not None


def _validate_bundle(bundle: Mapping[str, Any], label: str) -> None:
    if bundle.get("schema_version") != "ota-evidence/v1":
        raise EvidenceValidationError(f"{label}.schema_version must be 'ota-evidence/v1'")
    _reject_unknown_keys(bundle, _EVIDENCE_KEYS, label)
    release = bundle.get("release")
    if not isinstance(release, Mapping):
        raise EvidenceValidationError(f"{label}.release must be an object")
    _reject_unknown_keys(release, _RELEASE_KEYS, f"{label}.release")
    _require_non_empty_string(release, "name", f"{label}.release")
    _require_non_empty_string(release, "version", f"{label}.release")
    sbom = bundle.get("sbom")
    if not isinstance(sbom, Mapping):
        raise EvidenceValidationError(f"{label}.sbom must be an object")
    _reject_unknown_keys(sbom, _SBOM_KEYS, f"{label}.sbom")
    seen_components: set[str] = set()
    for index, component in enumerate(
        _require_list(sbom, "components", f"{label}.sbom")
    ):
        if not isinstance(component, Mapping):
            raise EvidenceValidationError(
                f"{label}.sbom.components[{index}] must be an object"
            )
        _reject_unknown_keys(
            component, _COMPONENT_KEYS, f"{label}.sbom.components[{index}]"
        )
        component_label = f"{label}.sbom.components[{index}]"
        for field in ("id", "purl", "name", "version"):
            _validate_optional_string(component, field, component_label)
        key = _component_key(component)
        if not key:
            raise EvidenceValidationError(
                f"{label}.sbom.components[{index}] needs id, purl, or name"
            )
        if key in seen_components:
            raise EvidenceValidationError(
                f"{label}: duplicate SBOM component identity {key!r}"
            )
        seen_components.add(key)
        _require_non_empty_string_list(component, "licenses", component_label)
    seen_interfaces: set[str] = set()
    for index, interface in enumerate(_require_list(bundle, "interfaces", label)):
        if not isinstance(interface, Mapping):
            raise EvidenceValidationError(
                f"{label}.interfaces[{index}] must be an object"
            )
        interface_label = f"{label}.interfaces[{index}]"
        _reject_unknown_keys(interface, _INTERFACE_KEYS, interface_label)
        interface_id = _require_non_empty_string(
            interface, "id", interface_label
        ).strip()
        for field in ("version", "contract_hash"):
            _validate_optional_string(interface, field, interface_label)
        if label == "baseline" and "contract_hash" in interface:
            baseline_contract_hash = str(interface["contract_hash"])
            if not _is_canonical_contract_hash(baseline_contract_hash):
                raise EvidenceValidationError(
                    f"{interface_label}.contract_hash must be 'sha256:' "
                    "followed by 64 lowercase hexadecimal characters"
                )
        if interface_id in seen_interfaces:
            raise EvidenceValidationError(
                f"{label}: duplicate interface identity {interface_id!r}"
            )
        seen_interfaces.add(interface_id)
        _require_non_empty_string_list(
            interface, "compatible_with", interface_label
        )
    for index, authority in enumerate(_require_list(bundle, "authorities", label)):
        if not isinstance(authority, Mapping):
            raise EvidenceValidationError(
                f"{label}.authorities[{index}] must be an object"
            )
        authority_label = f"{label}.authorities[{index}]"
        _reject_unknown_keys(authority, _AUTHORITY_KEYS, authority_label)
        _require_non_empty_string(authority, "principal", authority_label)
        _require_non_empty_string(authority, "resource", authority_label)
        _require_string_list(authority, "actions", authority_label)
    manifest = bundle.get("signed_manifest", {})
    if not isinstance(manifest, Mapping):
        raise EvidenceValidationError(f"{label}.signed_manifest must be an object")
    _reject_unknown_keys(manifest, _SIGNED_MANIFEST_KEYS, f"{label}.signed_manifest")
    _validate_optional_string(manifest, "artifact_digest", f"{label}.signed_manifest")
    verification = manifest.get("verification", {})
    if not isinstance(verification, Mapping):
        raise EvidenceValidationError(
            f"{label}.signed_manifest.verification must be an object"
        )
    _reject_unknown_keys(
        verification,
        _VERIFICATION_KEYS,
        f"{label}.signed_manifest.verification",
    )
    for field in ("status", "verifier", "identity"):
        _validate_optional_string(
            verification, field, f"{label}.signed_manifest.verification"
        )
    rollback = bundle.get("rollback", {})
    if not isinstance(rollback, Mapping):
        raise EvidenceValidationError(f"{label}.rollback must be an object")
    _reject_unknown_keys(rollback, _EVIDENCE_ROLLBACK_KEYS, f"{label}.rollback")
    for field in ("status", "procedure_id", "evidence_uri", "artifact_digest"):
        _validate_optional_string(rollback, field, f"{label}.rollback")


def _validate_policy(policy: Mapping[str, Any]) -> None:
    if policy.get("schema_version") != "ota-policy/v1":
        raise EvidenceValidationError("policy.schema_version must be 'ota-policy/v1'")
    _reject_unknown_keys(policy, _POLICY_KEYS, "policy")
    budgets = policy.get("risk_budgets", {})
    if not isinstance(budgets, Mapping):
        raise EvidenceValidationError("policy.risk_budgets must be an object")
    _reject_unknown_keys(budgets, _RISK_BUDGET_KEYS, "policy.risk_budgets")
    for name, maximum in budgets.items():
        if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 0:
            raise EvidenceValidationError(
                f"policy.risk_budgets.{name} must be a non-negative integer"
            )
    _require_non_empty_string_list(policy, "allowed_licenses", "policy")
    manifest = policy.get("manifest", {})
    rollback = policy.get("rollback", {})
    if not isinstance(manifest, Mapping):
        raise EvidenceValidationError("policy.manifest must be an object")
    if not isinstance(rollback, Mapping):
        raise EvidenceValidationError("policy.rollback must be an object")
    _reject_unknown_keys(manifest, _POLICY_MANIFEST_KEYS, "policy.manifest")
    _reject_unknown_keys(rollback, _POLICY_ROLLBACK_KEYS, "policy.rollback")
    _require_string_list(manifest, "accepted_verification_statuses", "policy.manifest")
    _validate_optional_bool(manifest, "require_artifact_digest", "policy.manifest")
    _require_string_list(rollback, "required_fields", "policy.rollback")
    _validate_optional_bool(rollback, "required", "policy.rollback")
    seen_exceptions: set[str] = set()
    for index, exception in enumerate(_require_list(policy, "exceptions", "policy")):
        if not isinstance(exception, Mapping):
            raise EvidenceValidationError(
                f"policy.exceptions[{index}] must be an object"
            )
        exception_label = f"policy.exceptions[{index}]"
        _reject_unknown_keys(exception, _EXCEPTION_KEYS, exception_label)
        exception_id = _require_non_empty_string(exception, "id", exception_label).strip()
        _require_non_empty_string(exception, "approved_by", exception_label)
        _require_non_empty_string(exception, "justification", exception_label)
        expires = _require_non_empty_string(
            exception, "expires", exception_label
        ).strip()
        if exception_id in seen_exceptions:
            raise EvidenceValidationError(
                f"duplicate policy exception id {exception_id!r}"
            )
        seen_exceptions.add(exception_id)
        try:
            date.fromisoformat(expires)
        except ValueError as error:
            raise EvidenceValidationError(
                f"policy.exceptions[{index}].expires must be an ISO date"
            ) from error
        if not _require_string_list(exception, "rule_ids", exception_label):
            raise EvidenceValidationError(
                f"policy.exceptions[{index}].rule_ids must not be empty"
            )
        _require_string_list(exception, "subjects", exception_label)


def _component_key(component: Mapping[str, Any]) -> str:
    for field in ("id", "purl", "name"):
        value = component.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _components(bundle: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    normalized: dict[str, dict[str, Any]] = {}
    sbom = bundle.get("sbom", {})
    for component in sbom.get("components", []):
        key = _component_key(component)
        if not key:
            continue
        normalized[key] = {
            "id": key,
            "name": str(component.get("name", key)).strip(),
            "version": str(component.get("version", "")).strip(),
            "licenses": sorted({str(item).strip() for item in component.get("licenses", [])}),
        }
    return normalized


def _finding(
    rule_id: str,
    severity: str,
    subject: str,
    message: str,
    **details: Any,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "status": "active",
        "subject": subject,
        "message": message,
        "details": details,
    }


def _release_findings(
    baseline: Mapping[str, Any], candidate: Mapping[str, Any]
) -> list[dict[str, Any]]:
    baseline_name = baseline["release"]["name"]
    candidate_name = candidate["release"]["name"]
    if baseline_name == candidate_name:
        return []
    return [
        _finding(
            "RELEASE.NAME_MISMATCH",
            "block",
            "release.name",
            "The candidate release name does not match the baseline release name.",
            baseline_release_name=baseline_name,
            candidate_release_name=candidate_name,
        )
    ]


def _sbom_findings(
    baseline: Mapping[str, Any], candidate: Mapping[str, Any], policy: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    old = _components(baseline)
    new = _components(candidate)
    findings: list[dict[str, Any]] = []
    metrics = {
        "new_dependencies": 0,
        "removed_dependencies": 0,
        "changed_dependencies": 0,
        "license_changes": 0,
    }
    allowed_licenses = {
        str(item).strip() for item in policy.get("allowed_licenses", [])
    }

    for component_id in sorted(new.keys() - old.keys()):
        metrics["new_dependencies"] += 1
        findings.append(
            _finding(
                "SBOM.DEPENDENCY_ADDED",
                "warn",
                component_id,
                f"The candidate adds dependency version {new[component_id]['version']}.",
                component=new[component_id],
            )
        )
    for component_id in sorted(old.keys() - new.keys()):
        metrics["removed_dependencies"] += 1
        findings.append(
            _finding(
                "SBOM.DEPENDENCY_REMOVED",
                "warn",
                component_id,
                f"The candidate removes dependency version {old[component_id]['version']}.",
                component=old[component_id],
            )
        )
    for component_id in sorted(old.keys() & new.keys()):
        before = old[component_id]
        after = new[component_id]
        if before["version"] != after["version"]:
            metrics["changed_dependencies"] += 1
            findings.append(
                _finding(
                    "SBOM.DEPENDENCY_CHANGED",
                    "warn",
                    component_id,
                    f"Dependency version changed from {before['version']} to {after['version']}.",
                    before=before["version"],
                    after=after["version"],
                )
            )
        if before["licenses"] != after["licenses"]:
            metrics["license_changes"] += 1
            findings.append(
                _finding(
                    "SBOM.LICENSE_CHANGED",
                    "warn",
                    component_id,
                    "Declared dependency licenses changed.",
                    before=before["licenses"],
                    after=after["licenses"],
                )
            )
    if allowed_licenses:
        for component_id in sorted(new):
            if not new[component_id]["licenses"]:
                findings.append(
                    _finding(
                        "SBOM.LICENSE_EVIDENCE_MISSING",
                        "block",
                        component_id,
                        "The candidate component has no declared license evidence.",
                    )
                )
                continue
            for license_id in new[component_id]["licenses"]:
                if license_id not in allowed_licenses:
                    findings.append(
                        _finding(
                            "SBOM.LICENSE_NOT_ALLOWED",
                            "block",
                            component_id,
                            f"License {license_id} is not in the policy allow-list.",
                            license=license_id,
                        )
                    )

    return findings, metrics


def _budget_findings(metrics: Mapping[str, int], policy: Mapping[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    budgets = policy.get("risk_budgets", {})
    for metric, actual in sorted(metrics.items()):
        if metric not in budgets:
            continue
        maximum = int(budgets[metric])
        if actual > maximum:
            findings.append(
                _finding(
                    f"RISK_BUDGET.{metric.upper()}_EXCEEDED",
                    "block",
                    metric,
                    f"Observed {actual}; policy permits at most {maximum}.",
                    actual=actual,
                    maximum=maximum,
                )
            )
    return findings


def _interface_findings(
    baseline: Mapping[str, Any], candidate: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    old = {
        str(item.get("id", "")).strip(): item
        for item in baseline.get("interfaces", [])
        if str(item.get("id", "")).strip()
    }
    new = {
        str(item.get("id", "")).strip(): item
        for item in candidate.get("interfaces", [])
        if str(item.get("id", "")).strip()
    }
    findings: list[dict[str, Any]] = []
    removed = sorted(old.keys() - new.keys())
    for interface_id in removed:
        findings.append(
            _finding(
                "INTERFACE.REMOVED",
                "block",
                interface_id,
                "A baseline interface is absent from the candidate release.",
                baseline_version=str(old[interface_id].get("version", "")),
            )
        )
    incompatible_count = 0
    for interface_id in sorted(old.keys() & new.keys()):
        before_hash = str(old[interface_id].get("contract_hash", ""))
        after_hash = str(new[interface_id].get("contract_hash", ""))
        if not before_hash:
            continue
        if not after_hash.strip() or not _is_canonical_contract_hash(after_hash):
            incompatible_count += 1
            reason = (
                "missing_contract_hash"
                if not after_hash.strip()
                else "invalid_contract_hash"
            )
            findings.append(
                _finding(
                    "INTERFACE.MISSING_CONTRACT_EVIDENCE",
                    "block",
                    interface_id,
                    "The baseline pins an interface contract, but the candidate "
                    "does not provide a valid non-empty contract hash.",
                    baseline_contract_hash=before_hash,
                    candidate_contract_hash=after_hash,
                    baseline_version=str(old[interface_id].get("version", "")),
                    candidate_version=str(new[interface_id].get("version", "")),
                    reason=reason,
                )
            )
            continue
        if before_hash == after_hash:
            continue
        compatible_with = {
            str(item).strip() for item in new[interface_id].get("compatible_with", [])
        }
        baseline_version = str(old[interface_id].get("version", "")).strip()
        if before_hash in compatible_with or (
            baseline_version and baseline_version in compatible_with
        ):
            continue
        incompatible_count += 1
        findings.append(
            _finding(
                "INTERFACE.INCOMPATIBLE",
                "block",
                interface_id,
                "The interface contract changed without compatibility evidence for the baseline.",
                baseline_contract_hash=before_hash,
                candidate_contract_hash=after_hash,
                baseline_version=baseline_version,
                candidate_version=str(new[interface_id].get("version", "")),
            )
        )
    return findings, {
        "removed_interfaces": len(removed),
        "incompatible_interfaces": incompatible_count,
    }


def _authority_tuples(bundle: Mapping[str, Any]) -> set[tuple[str, str, str]]:
    grants: set[tuple[str, str, str]] = set()
    for authority in bundle.get("authorities", []):
        principal = str(authority.get("principal", "")).strip()
        resource = str(authority.get("resource", "")).strip()
        for action in authority.get("actions", []):
            action_name = str(action).strip()
            if principal and resource and action_name:
                grants.add((principal, resource, action_name))
    return grants


def _authority_findings(
    baseline: Mapping[str, Any], candidate: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    baseline_grants = _authority_tuples(baseline)
    candidate_grants = _authority_tuples(candidate)
    expansions = sorted(candidate_grants - baseline_grants)
    contractions = sorted(baseline_grants - candidate_grants)
    findings = [
        _finding(
            "AUTHORITY.PRIVILEGE_EXPANSION",
            "block",
            "|".join(grant),
            "The candidate adds an authority tuple not present in the baseline.",
            principal=grant[0],
            resource=grant[1],
            action=grant[2],
        )
        for grant in expansions
    ]
    findings.extend(
        _finding(
            "AUTHORITY.PRIVILEGE_CONTRACTION",
            "info",
            "|".join(grant),
            "The candidate removes an authority tuple present in the baseline.",
            principal=grant[0],
            resource=grant[1],
            action=grant[2],
        )
        for grant in contractions
    )
    return findings, {
        "privilege_expansions": len(expansions),
        "privilege_contractions": len(contractions),
    }


def _rollback_findings(
    candidate: Mapping[str, Any], policy: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    if not bool(policy.get("rollback", {}).get("required", False)):
        return [], {"rollback_failures": 0}
    rollback = candidate.get("rollback")
    if not isinstance(rollback, Mapping):
        return [
            _finding(
                "ROLLBACK.EVIDENCE_MISSING",
                "block",
                "rollback",
                "Policy requires rollback evidence, but the candidate supplies none.",
            )
        ], {"rollback_failures": 1}
    findings: list[dict[str, Any]] = []
    status = str(rollback.get("status", "missing")).strip().lower()
    if status != "pass":
        rule_id = "ROLLBACK.TEST_FAILED" if status == "fail" else "ROLLBACK.TEST_NOT_PASSED"
        findings.append(
            _finding(
                rule_id,
                "block",
                str(rollback.get("procedure_id", "rollback")),
                f"Rollback evidence status is {status!r}, not 'pass'.",
                status=status,
            )
        )
    required_fields = policy.get("rollback", {}).get(
        "required_fields", ["procedure_id", "evidence_uri", "artifact_digest"]
    )
    missing = sorted(
        str(field)
        for field in required_fields
        if not str(rollback.get(str(field), "")).strip()
    )
    if missing:
        findings.append(
            _finding(
                "ROLLBACK.EVIDENCE_INCOMPLETE",
                "block",
                str(rollback.get("procedure_id", "rollback")),
                "Rollback evidence omits policy-required metadata fields.",
                missing_fields=missing,
            )
        )
    manifest = candidate.get("signed_manifest", {})
    manifest_digest = str(manifest.get("artifact_digest", "")).strip()
    rollback_digest = str(rollback.get("artifact_digest", "")).strip()
    if manifest_digest and rollback_digest and manifest_digest != rollback_digest:
        findings.append(
            _finding(
                "ROLLBACK.ARTIFACT_DIGEST_MISMATCH",
                "block",
                str(rollback.get("procedure_id", "rollback")),
                "Rollback evidence is bound to a different artifact digest.",
                manifest_artifact_digest=manifest_digest,
                rollback_artifact_digest=rollback_digest,
            )
        )
    return findings, {"rollback_failures": int(bool(findings))}


def _manifest_findings(
    candidate: Mapping[str, Any], policy: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    manifest = candidate.get("signed_manifest", {})
    verification = manifest.get("verification", {}) if isinstance(manifest, Mapping) else {}
    status = str(verification.get("status", "missing")).strip().lower()
    accepted = {
        str(item).strip().lower()
        for item in policy.get("manifest", {}).get(
            "accepted_verification_statuses", ["verified"]
        )
    }
    findings: list[dict[str, Any]] = []
    if bool(policy.get("manifest", {}).get("require_artifact_digest", True)) and not str(
        manifest.get("artifact_digest", "")
    ).strip():
        findings.append(
            _finding(
                "MANIFEST.ARTIFACT_DIGEST_MISSING",
                "block",
                "signed_manifest.artifact_digest",
                "Signed-manifest metadata does not identify the evaluated artifact digest.",
            )
        )
    if status not in accepted:
        findings.append(
            _finding(
                "MANIFEST.VERIFICATION_STATUS_REJECTED",
                "block",
                "signed_manifest.verification.status",
                f"Supplied verification status {status!r} is not accepted by policy.",
                supplied_status=status,
                accepted_statuses=sorted(accepted),
            )
        )
    return findings, {"manifest_verification_failures": int(bool(findings))}


_RULE_METRICS = {
    "SBOM.DEPENDENCY_ADDED": "new_dependencies",
    "SBOM.DEPENDENCY_REMOVED": "removed_dependencies",
    "SBOM.DEPENDENCY_CHANGED": "changed_dependencies",
    "SBOM.LICENSE_CHANGED": "license_changes",
    "INTERFACE.REMOVED": "removed_interfaces",
    "INTERFACE.MISSING_CONTRACT_EVIDENCE": "incompatible_interfaces",
    "INTERFACE.INCOMPATIBLE": "incompatible_interfaces",
    "AUTHORITY.PRIVILEGE_EXPANSION": "privilege_expansions",
    "AUTHORITY.PRIVILEGE_CONTRACTION": "privilege_contractions",
    "ROLLBACK.EVIDENCE_MISSING": "rollback_failures",
    "ROLLBACK.TEST_FAILED": "rollback_failures",
    "ROLLBACK.TEST_NOT_PASSED": "rollback_failures",
    "ROLLBACK.EVIDENCE_INCOMPLETE": "rollback_failures",
    "ROLLBACK.ARTIFACT_DIGEST_MISMATCH": "rollback_failures",
    "MANIFEST.VERIFICATION_STATUS_REJECTED": "manifest_verification_failures",
    "MANIFEST.ARTIFACT_DIGEST_MISSING": "manifest_verification_failures",
}


def _apply_exceptions(
    findings: list[dict[str, Any]],
    metrics: dict[str, int],
    policy: Mapping[str, Any],
    evaluation_date: date,
) -> None:
    exceptions = sorted(policy.get("exceptions", []), key=lambda item: str(item.get("id", "")))
    expired: dict[str, dict[str, Any]] = {}
    for finding in list(findings):
        for exception in exceptions:
            exception_id = str(exception.get("id", "")).strip()
            approved_by = str(exception.get("approved_by", "")).strip()
            justification = str(exception.get("justification", "")).strip()
            expires_raw = str(exception.get("expires", "")).strip()
            if not (exception_id and approved_by and justification and expires_raw):
                continue
            try:
                expires = date.fromisoformat(expires_raw)
            except ValueError:
                continue
            rule_ids = {str(item) for item in exception.get("rule_ids", [])}
            subjects = {str(item) for item in exception.get("subjects", [])}
            if finding["rule_id"] not in rule_ids and "*" not in rule_ids:
                continue
            if subjects and finding["subject"] not in subjects and "*" not in subjects:
                continue
            if expires < evaluation_date:
                expired.setdefault(exception_id, {"expires": expires.isoformat()})
                continue
            finding["status"] = "excepted"
            finding["exception_id"] = exception_id
            finding["exception_expires"] = expires.isoformat()
            metric = _RULE_METRICS.get(finding["rule_id"])
            if metric is not None and metrics.get(metric, 0) > 0:
                metrics[metric] -= 1
            break
    for exception_id, metadata in sorted(expired.items()):
        findings.append(
            _finding(
                "EXCEPTION.EXPIRED",
                "warn",
                exception_id,
                f"A matching policy exception expired on {metadata['expires']}.",
                expires=metadata["expires"],
            )
        )


def evaluate_release(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
    policy: Mapping[str, Any],
    *,
    as_of: str | date,
) -> dict[str, Any]:
    """Evaluate a candidate bundle against a baseline and policy.

    ``as_of`` is explicit so identical inputs always produce identical output.
    The function consumes verification *metadata* and does not verify signatures.
    """

    evaluation_date = date.fromisoformat(as_of) if isinstance(as_of, str) else as_of
    _validate_bundle(baseline, "baseline")
    _validate_bundle(candidate, "candidate")
    _validate_policy(policy)
    findings = _release_findings(baseline, candidate)
    sbom_findings, metrics = _sbom_findings(baseline, candidate, policy)
    findings.extend(sbom_findings)
    interface_findings, interface_metrics = _interface_findings(baseline, candidate)
    findings.extend(interface_findings)
    metrics.update(interface_metrics)
    authority_findings, authority_metrics = _authority_findings(baseline, candidate)
    findings.extend(authority_findings)
    metrics.update(authority_metrics)
    rollback_findings, rollback_metrics = _rollback_findings(candidate, policy)
    findings.extend(rollback_findings)
    metrics.update(rollback_metrics)
    manifest_findings, manifest_metrics = _manifest_findings(candidate, policy)
    findings.extend(manifest_findings)
    metrics.update(manifest_metrics)
    raw_metrics = dict(metrics)
    _apply_exceptions(findings, metrics, policy, evaluation_date)
    findings.extend(_budget_findings(metrics, policy))
    findings.sort(key=lambda item: (item["rule_id"], item["subject"], item["message"]))
    active_findings = [item for item in findings if item["status"] == "active"]
    decision = (
        "block"
        if any(item["severity"] == "block" for item in active_findings)
        else "warn"
        if any(item["severity"] == "warn" for item in active_findings)
        else "pass"
    )
    return {
        "schema_version": "ota-policy-report/v1",
        "decision": decision,
        "evaluation_date": evaluation_date.isoformat(),
        "baseline_release": deepcopy(dict(baseline.get("release", {}))),
        "candidate_release": deepcopy(dict(candidate.get("release", {}))),
        "findings": findings,
        "risk_usage": dict(sorted(metrics.items())),
        "risk_usage_before_exceptions": dict(sorted(raw_metrics.items())),
        "evidence_notice": (
            "Verification status is caller-supplied evidence; ota-policy-gate does not "
            "perform or replace cryptographic signature verification."
        ),
        "policy_schema_version": policy.get("schema_version", "unknown"),
    }
