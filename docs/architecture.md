# Architecture and evidence design

## Purpose and boundary

The package makes one deterministic decision from three caller-controlled JSON
objects: a baseline evidence bundle, a candidate evidence bundle, and a policy.
It intentionally performs no network lookup, package resolution, signature
verification, certificate validation, artifact download, or device action.

The signed-manifest field is a trust boundary. A cryptographic verifier must run
outside this process. Its status (`verified`, `failed`, or another locally
defined value), verifier identity, and artifact digest are evidence inputs. The
gate checks those values against policy but cannot prove that they are true.

## Data flow

1. The CLI parses JSON, rejects duplicate object keys, and supplies an explicit
   evaluation date.
2. Structural validation rejects unknown fields, wrong scalar types, ambiguous
   schemas, duplicate component IDs, and unsafe display text.
3. Domain comparators normalize records and emit findings plus numeric risk
   usage.
4. Active, approved exceptions annotate matching findings and remove their
   units from effective risk usage.
5. Risk-budget rules evaluate the effective usage.
6. The highest active severity determines `pass`, `warn`, or `block`.
7. JSON and Markdown renderers sort keys, metrics, and findings and add a single
   final newline.
   Markdown code spans select a delimiter longer than every embedded backtick
   run and escape table separators after validating the original text.

There is no hidden state and no wall-clock read. The same input objects and
`as_of` date produce the same report.

## Versioned schemas

### `ota-evidence/v1`

The top-level object allows exactly `schema_version`, `release`, `sbom`,
`signed_manifest`, `interfaces`, `authorities`, and `rollback`. `release` and
`sbom` are structural inputs. Missing or incomplete manifest and rollback
evidence remains representable so policy evaluation can emit the existing
blocking findings.

Nested objects are also closed:

- `release` allows only `name` and `version`; both are required non-empty
  strings. Validation is per bundle, then comparison requires the baseline and
  candidate names to be exactly equal.
- `sbom` allows only `components`. Each component allows `id`, `purl`, `name`,
  `version`, and `licenses`; at least one of `id`, `purl`, or `name` must provide
  a non-empty identity, supplied scalar values must be strings, and `licenses`
  is an array whose entries, when present, are non-empty strings.
- An interface allows `id`, `version`, `contract_hash`, and `compatible_with`.
  Its `id` is a non-empty string. A baseline `contract_hash`, when supplied,
  must be canonical `sha256:` plus exactly 64 lowercase hexadecimal
  characters. Candidate contract evidence is checked against that same
  canonical form during comparison so malformed evidence produces an
  auditable release finding. `version` is a string when supplied, and all
  `compatible_with` entries are non-empty strings.
- An authority allows `principal`, `resource`, and `actions`. Principal and
  resource are non-empty strings, and actions is an array of strings.
- `signed_manifest` allows `artifact_digest` and `verification`; verification
  allows `status`, `verifier`, and `identity`. Supplied scalar values are
  strings.
- `rollback` allows `status`, `procedure_id`, `evidence_uri`, and
  `artifact_digest`, all strings when supplied.

The schema is deliberately a small normalized interchange model rather than a
CycloneDX or SPDX parser. Convert a source SBOM into stable component identities
before invoking the gate. This avoids silently guessing ecosystem-specific
identity rules.

### `ota-policy/v1`

The top-level policy object allows exactly `schema_version`, `manifest`,
`allowed_licenses`, `rollback`, `risk_budgets`, and `exceptions`.

- `manifest` allows `accepted_verification_statuses` (an array of strings) and
  `require_artifact_digest` (a Boolean).
- `allowed_licenses`, when non-empty, is an exact array of non-empty license-ID
  strings. It activates a fail-closed allow-list: a candidate component with no
  declared license evidence is blocked rather than silently skipped.
- `rollback` allows `required` (a Boolean) and `required_fields` (an array of
  strings). The latter can override the default `procedure_id`, `evidence_uri`,
  and `artifact_digest`.
- `risk_budgets` accepts the metric keys `new_dependencies`,
  `removed_dependencies`, `changed_dependencies`, `license_changes`,
  `removed_interfaces`, `incompatible_interfaces`, `privilege_expansions`,
  `privilege_contractions`, `rollback_failures`, and
  `manifest_verification_failures`. Values are non-negative integers; JSON
  Booleans are not accepted as integers.
- Each exception allows exactly `id`, `rule_ids`, `subjects`, `expires`,
  `approved_by`, and `justification`. Required scalar values and every array
  entry are strings.

The Python API applies the same type rules as the CLI. It does not convert
integers or Booleans to strings, or strings and integers to Booleans.

All externally supplied human-readable string fields in both schemas pass the
same text validator. It rejects Unicode categories `Cc` (controls), `Cf`
(formatting, including bidi overrides), `Cs`/`Co`/`Cn` surrogate, private-use,
and unassigned values, `Zl`/`Zp` line and paragraph
separators, and other non-ASCII whitespace that can render ambiguously.
Ordinary non-ASCII letters, marks, numbers, and punctuation remain unchanged.
The JSON and Markdown renderers apply this validator to every rendered field, including
release labels, metric names, finding fields, exception IDs, and notices, even
when callers construct a report dictionary directly.

### `ota-policy-report/v1`

The report includes release identities, decision, explicit evaluation date,
sorted findings, effective risk usage, pre-exception risk usage, and an evidence
boundary notice. A finding has `rule_id`, `severity`, `status`, `subject`,
`message`, and structured `details`. Excepted findings also identify the
exception and expiry date. A release-name mismatch records
`baseline_release_name` and `candidate_release_name` in `details`; these are the
same validated caller-supplied values already present in the report's release
identities.

## Comparison semantics

Release lineage is the literal, case-sensitive `release.name`. The baseline and
candidate values must be exactly equal; the gate performs no case folding,
whitespace normalization, alias lookup, or rename mapping. A mismatch emits the
blocking `RELEASE.NAME_MISMATCH` finding with subject `release.name`.
`release.version` may differ because it identifies the release on each side of
the comparison.

SBOM identity is the first non-empty trimmed value among `id`, `purl`, and
`name`, converted to lowercase. Whitespace-only higher-priority fields do not
mask a usable fallback. Versions and sorted unique license strings are compared
literally.

Interface removal is blocking. If a baseline interface pins a canonical
`contract_hash`, the corresponding candidate must provide its own canonical
non-empty hash. Omitted, empty, malformed, or downgraded candidate hashes emit
the blocking `INTERFACE.MISSING_CONTRACT_EVIDENCE` finding even if
`compatible_with` is present. Equal hashes pass. Different canonical hashes
pass only when candidate `compatible_with` explicitly lists the non-empty
baseline hash or baseline version; otherwise
`INTERFACE.INCOMPATIBLE` blocks the release.

Authority records are flattened into exact `(principal, resource, action)`
tuples. Additions are blocking expansions. Removals are informational
contractions unless a configured budget makes their count blocking.

Rollback evidence must pass, contain required metadata, and name the same
artifact digest as the candidate signed-manifest metadata.

## Exception semantics

Exceptions are sorted by ID. A finding is waived by the first exception that:

1. contains non-empty `id`, `approved_by`, and `justification` fields;
2. has a valid `expires` date on or after `as_of`;
3. matches the finding rule (or `*`); and
4. matches the finding subject (or `*`; omitted subjects match any subject).

Expired matching exceptions emit `EXCEPTION.EXPIRED` and do not waive the
underlying finding. Policy owners should avoid wildcard exceptions for
safety-relevant rules. `RELEASE.NAME_MISMATCH` participates in this existing
finding-exception mechanism; the policy schema adds no rename or alias feature.

An excepted budgetable finding subtracts one available unit from its effective
metric before risk budgets are evaluated. The raw count remains in
`risk_usage_before_exceptions`. The complete finding-to-metric association is:

| Risk metric | Contributing finding rules |
|---|---|
| `new_dependencies` | `SBOM.DEPENDENCY_ADDED` |
| `removed_dependencies` | `SBOM.DEPENDENCY_REMOVED` |
| `changed_dependencies` | `SBOM.DEPENDENCY_CHANGED` |
| `license_changes` | `SBOM.LICENSE_CHANGED` |
| `removed_interfaces` | `INTERFACE.REMOVED` |
| `incompatible_interfaces` | `INTERFACE.MISSING_CONTRACT_EVIDENCE`, `INTERFACE.INCOMPATIBLE` |
| `privilege_expansions` | `AUTHORITY.PRIVILEGE_EXPANSION` |
| `privilege_contractions` | `AUTHORITY.PRIVILEGE_CONTRACTION` |
| `rollback_failures` | `ROLLBACK.EVIDENCE_MISSING`, `ROLLBACK.TEST_FAILED`, `ROLLBACK.TEST_NOT_PASSED`, `ROLLBACK.EVIDENCE_INCOMPLETE`, `ROLLBACK.ARTIFACT_DIGEST_MISMATCH` |
| `manifest_verification_failures` | `MANIFEST.VERIFICATION_STATUS_REJECTED`, `MANIFEST.ARTIFACT_DIGEST_MISSING` |

## Extension points

New evidence comparators should return findings and integer metrics, add stable
rule IDs, and remain pure functions. New report fields must be deterministic and
must not include host paths, current timestamps, random IDs, or environment
values. A schema version change is required for incompatible field semantics.
