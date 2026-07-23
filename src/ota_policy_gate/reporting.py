"""Deterministic report renderers."""

from __future__ import annotations

import json
from typing import Any, Mapping

from .validation import validate_human_readable_text


def _validate_report_text(value: Any, label: str = "JSON report") -> None:
    if isinstance(value, str):
        validate_human_readable_text(value, label)
    elif isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str):
                validate_human_readable_text(key, f"{label} key")
            _validate_report_text(item, f"{label}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_report_text(item, f"{label}[{index}]")


def render_json(report: Mapping[str, Any]) -> str:
    """Render a canonical, human-readable JSON report with a final newline."""

    _validate_report_text(report)
    return json.dumps(
        report,
        ensure_ascii=False,
        allow_nan=False,
        indent=2,
        sort_keys=True,
    ) + "\n"


def _markdown_text(value: Any) -> str:
    return validate_human_readable_text(str(value), "Markdown report text")


def _cell(value: Any) -> str:
    return _markdown_text(value).replace("|", "\\|")


def _code_span(value: Any) -> str:
    """Render one table-safe CommonMark code span without delimiter collision."""

    text = _cell(value)
    longest_run = 0
    current_run = 0
    for character in text:
        if character == "`":
            current_run += 1
            longest_run = max(longest_run, current_run)
        else:
            current_run = 0
    delimiter = "`" * (longest_run + 1)
    if text.startswith("`") or text.endswith("`"):
        return f"{delimiter} {text} {delimiter}"
    return f"{delimiter}{text}{delimiter}"


def _release_label(value: Any) -> str:
    if not isinstance(value, Mapping):
        return "unknown"
    name = str(value.get("name", "unknown"))
    version = str(value.get("version", "unknown"))
    return f"{name} {version}"


def render_markdown(report: Mapping[str, Any]) -> str:
    """Render a stable Markdown decision report."""

    decision = _markdown_text(report.get("decision", "unknown")).upper()
    evidence_notice = _markdown_text(
        report.get("evidence_notice", "No evidence notice supplied.")
    )
    lines = [
        "# OTA policy decision",
        "",
        f"- Decision: **{decision}**",
        f"- Evaluation date: {_code_span(report.get('evaluation_date', 'unknown'))}",
        f"- Baseline: {_code_span(_release_label(report.get('baseline_release')))}",
        f"- Candidate: {_code_span(_release_label(report.get('candidate_release')))}",
        "",
        "## Evidence boundary",
        "",
        evidence_notice,
        "",
        "## Risk usage",
        "",
        "| Metric | Effective | Before exceptions |",
        "|---|---:|---:|",
    ]
    effective = report.get("risk_usage", {})
    raw = report.get("risk_usage_before_exceptions", effective)
    for metric in sorted(set(effective) | set(raw)):
        lines.append(
            f"| {_code_span(metric)} | {_cell(effective.get(metric, 0))} | {_cell(raw.get(metric, 0))} |"
        )

    lines.extend(
        [
            "",
            "## Findings",
            "",
            "| Rule ID | Severity | Status | Subject | Explanation |",
            "|---|---|---|---|---|",
        ]
    )
    findings = sorted(
        report.get("findings", []),
        key=lambda item: (
            str(item.get("rule_id", "")),
            str(item.get("subject", "")),
            str(item.get("message", "")),
        ),
    )
    if not findings:
        lines.append("| - | - | - | - | No findings. |")
    for finding in findings:
        status = str(finding.get("status", "active"))
        if finding.get("exception_id"):
            status += f" ({finding['exception_id']})"
        lines.append(
            "| {rule} | {severity} | {status} | {subject} | {message} |".format(
                rule=_code_span(finding.get("rule_id", "unknown")),
                severity=_code_span(finding.get("severity", "unknown")),
                status=_code_span(status),
                subject=_code_span(finding.get("subject", "unknown")),
                message=_cell(finding.get("message", "")),
            )
        )
    return "\n".join(lines) + "\n"
