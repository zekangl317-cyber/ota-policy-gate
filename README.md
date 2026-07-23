# ota-policy-gate

[English](README.md) | [简体中文](README.zh-CN.md)

`ota-policy-gate` is a Python 3.11+ release/CI gate for over-the-air update
evidence. It compares a normalized baseline bundle with a candidate bundle,
applies an explicit policy, and emits deterministic JSON and Markdown reports.
The runtime has no third-party dependencies.

The gate joins seven evidence domains:

- exact baseline-to-candidate release-name lineage;
- normalized SBOM dependency and license deltas;
- caller-supplied signed-manifest verification metadata;
- interface removal and contract-compatibility evidence;
- authority tuple expansion and contraction;
- rollback test status, metadata completeness, and artifact binding; and
- per-delta risk budgets with approved, expiring exceptions.

This project **does not verify signatures and does not implement cryptography**.
Run a real signature verifier before this gate and supply its status and
metadata in `signed_manifest.verification`. The gate orchestrates that evidence;
it does not replace the verifier, a transparency log, an SBOM generator, or a
safety case.

## Windows quickstart (no installation)

From the repository root in PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m ota_policy_gate evaluate `
  --baseline examples/fixtures/baseline.json `
  --candidate examples/fixtures/candidate-safe.json `
  --policy examples/fixtures/policy.json `
  --as-of 2026-07-23 `
  --json-out decision.json `
  --markdown-out decision.md
```

The safe fixture exits `0`. To exercise a blocking decision, replace
`candidate-safe.json` with `candidate-risky.json`; that command exits `20`.
An editable install is optional:

```powershell
python -m pip install --no-build-isolation -e .
ota-policy-gate --help
```

No GPU, network, cloud account, Docker, WSL, paid API, sibling repository, or
hardware target is used.

## CLI contract

```text
ota-policy-gate evaluate --baseline FILE --candidate FILE --policy FILE \
  --as-of YYYY-MM-DD [--json-out FILE] [--markdown-out FILE] [--quiet]
```

`--as-of` is mandatory. Exception expiry therefore never depends on the local
clock, which keeps repeated evaluations byte-stable. If no output path is
given, the JSON report is written to stdout.

The CLI rejects duplicate JSON object keys at any nesting level. The versioned
evidence and policy schemas also reject unknown fields and scalar type
coercion; these conditions are input errors rather than release findings.

| Outcome | Exit code | Meaning |
|---|---:|---|
| pass | 0 | no active block or warning finding |
| warn | 10 | active warning findings, no active block |
| block | 20 | one or more active block findings |
| input error | 64 | malformed JSON, schema, date, or output failure |

CI systems should treat both `10` and `20` according to local release policy;
the distinct values allow warning-only pipelines.

## Evidence bundle shape

Inputs use `schema_version: "ota-evidence/v1"`. The baseline and candidate
`release.name` values must match exactly, including case and whitespace; no
alias or rename field is defined. A mismatch emits the blocking
`RELEASE.NAME_MISMATCH` finding with both validated names in its structured
details. `release.version` identifies each side independently and may change.

Component `id` values must be stable across versions (for example
`pkg:pypi/requests`, without a version in the identifier); `version` carries
the changing version. Authority is normalized to `(principal, resource,
action)` tuples. Interface compatibility is established by an unchanged
`contract_hash` or by listing the baseline hash or version in candidate
`compatible_with`. Contract hashes use the canonical form `sha256:` followed
by exactly 64 lowercase hexadecimal characters. When a baseline interface
pins a contract hash, omitting, emptying, corrupting, or downgrading the
candidate hash emits the blocking
`INTERFACE.MISSING_CONTRACT_EVIDENCE` finding; `compatible_with` cannot replace
the candidate's own valid hash.

Version 1 object shapes are closed: fields not listed in the architecture
document are rejected. In particular, `release.name` and `release.version` are
required non-empty strings, and string, integer, and Boolean fields are not
coerced from other JSON scalar types.

Every supplied human-readable evidence/policy string field passes one shared
display-text check.
Unicode control (`Cc`) and format (`Cf`) characters, surrogate, private-use,
and unassigned code points, Unicode line/paragraph
separators, and other ambiguous non-ASCII whitespace are rejected with the
offending code point. Ordinary international letters and punctuation are
preserved. The JSON and Markdown renderers apply the same rule to hand-built report
objects before escaping table pipes or selecting code-span delimiters.

The fixtures under [`examples/fixtures`](examples/fixtures) are executable
examples, not attestations about a real device. See
[`docs/architecture.md`](docs/architecture.md) for the complete data model and
trust boundary.

## Core rule IDs

Reports explain decisions with stable IDs, including:

- `RELEASE.NAME_MISMATCH`;
- `SBOM.DEPENDENCY_ADDED`, `SBOM.DEPENDENCY_CHANGED`,
  `SBOM.DEPENDENCY_REMOVED`, `SBOM.LICENSE_CHANGED`, and
  `SBOM.LICENSE_EVIDENCE_MISSING` and `SBOM.LICENSE_NOT_ALLOWED`;
- `MANIFEST.VERIFICATION_STATUS_REJECTED` and
  `MANIFEST.ARTIFACT_DIGEST_MISSING`;
- `INTERFACE.REMOVED`, `INTERFACE.MISSING_CONTRACT_EVIDENCE`, and
  `INTERFACE.INCOMPATIBLE`;
- `AUTHORITY.PRIVILEGE_EXPANSION` and
  `AUTHORITY.PRIVILEGE_CONTRACTION`;
- `ROLLBACK.TEST_FAILED`, `ROLLBACK.TEST_NOT_PASSED`,
  `ROLLBACK.EVIDENCE_INCOMPLETE`, and
  `ROLLBACK.ARTIFACT_DIGEST_MISMATCH`; and
- `RISK_BUDGET.<METRIC>_EXCEEDED` and `EXCEPTION.EXPIRED`.

Caller-supplied labels in Markdown reports use collision-free CommonMark code
spans, with pipes made table-safe. Physical and Unicode line breaks are invalid
report text and are rejected rather than rewritten.

An exception applies only when it has an ID, approver, justification, ISO expiry
date, matching rule ID, and matching subject. Active exceptions remain visible
as `status: "excepted"`; they are never deleted from the report. An excepted
budgetable finding removes one available unit from its associated effective
risk metric before budgets are evaluated, including authority contractions.
`risk_usage_before_exceptions` preserves the original usage.

## Python API

```python
from ota_policy_gate import evaluate_release, render_json, render_markdown

report = evaluate_release(baseline, candidate, policy, as_of="2026-07-23")
json_text = render_json(report)
markdown_text = render_markdown(report)
```

The API returns ordinary dictionaries so callers can archive, sign, or wrap the
decision using their own infrastructure.

## Tests

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
$env:PYTHONPATH = "src"
python -B -m unittest discover -s tests -v
```

The tests cover deterministic output, malformed input, dependency and license
drift, missing license evidence under an active allow-list, component-identity
fallback, exact release lineage, removed and incompatible interfaces, privilege
changes, rollback failures, supplied verification status, risk budgets, and
active/expired exceptions.

## Project status

Version 0.1.0 is a focused policy engine and reference schema. It has not been
certified for any safety, aviation, automotive, medical, or regulatory regime.
Adopters must review rule severity, evidence provenance, and exception approval
workflow for their own system.
