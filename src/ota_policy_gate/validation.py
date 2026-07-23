"""Shared validation for externally supplied human-readable text."""

from __future__ import annotations

import unicodedata


class EvidenceValidationError(ValueError):
    """Raised when an evidence bundle, policy, or report is ambiguous."""


def validate_human_readable_text(value: str, label: str) -> str:
    """Reject invisible controls and ambiguous separators without ASCII folding."""

    for character in value:
        category = unicodedata.category(character)
        if category == "Cc":
            kind = "control"
        elif category == "Cf":
            kind = "format"
        elif category == "Cs":
            kind = "surrogate"
        elif category == "Co":
            kind = "private-use"
        elif category == "Cn":
            kind = "unassigned"
        elif category == "Zl":
            kind = "line separator"
        elif category == "Zp":
            kind = "paragraph separator"
        elif character.isspace() and character != " ":
            kind = "ambiguous whitespace"
        else:
            continue
        raise EvidenceValidationError(
            f"{label} contains disallowed Unicode {kind} character "
            f"U+{ord(character):04X}"
        )
    return value
