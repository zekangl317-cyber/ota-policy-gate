"""Command-line interface for OTA policy evaluation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from .policy import evaluate_release
from .reporting import render_json, render_markdown


PASS_EXIT = 0
WARN_EXIT = 10
BLOCK_EXIT = 20
INPUT_ERROR_EXIT = 64


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ota-policy-gate",
        description="Join caller-supplied OTA evidence into an explainable release decision.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    evaluate = subparsers.add_parser("evaluate", help="evaluate baseline and candidate bundles")
    evaluate.add_argument("--baseline", type=Path, required=True)
    evaluate.add_argument("--candidate", type=Path, required=True)
    evaluate.add_argument("--policy", type=Path, required=True)
    evaluate.add_argument(
        "--as-of",
        required=True,
        help="ISO date used for deterministic exception-expiry evaluation",
    )
    evaluate.add_argument("--json-out", type=Path)
    evaluate.add_argument("--markdown-out", type=Path)
    evaluate.add_argument(
        "--quiet",
        action="store_true",
        help="do not also print the JSON report to standard output",
    )
    return parser


def _object_without_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate object key {key!r}")
        value[key] = item
    return value


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_object_without_duplicate_keys,
    )
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level JSON value must be an object")
    return value


def _write_text(path: Path, value: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(value)


def decision_exit_code(decision: str) -> int:
    return {"pass": PASS_EXIT, "warn": WARN_EXIT, "block": BLOCK_EXIT}[decision]


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command != "evaluate":  # pragma: no cover - argparse enforces this
        return INPUT_ERROR_EXIT
    try:
        report = evaluate_release(
            _load_json(args.baseline),
            _load_json(args.candidate),
            _load_json(args.policy),
            as_of=args.as_of,
        )
        json_report = render_json(report)
        markdown_report = render_markdown(report)
        if args.json_out is not None:
            _write_text(args.json_out, json_report)
        if args.markdown_out is not None:
            _write_text(args.markdown_out, markdown_report)
        if not args.quiet:
            sys.stdout.write(json_report)
        return decision_exit_code(report["decision"])
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        sys.stderr.write(f"ota-policy-gate: input error: {error}\n")
        return INPUT_ERROR_EXIT


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
