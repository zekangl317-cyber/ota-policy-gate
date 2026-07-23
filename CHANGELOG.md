# Changelog

All notable changes are documented here. This project follows semantic
versioning while its JSON schemas are versioned independently.

## [Unreleased]

### Fixed

- Render caller-supplied report labels with collision-free Markdown code spans,
  including embedded backticks and pipes.
- Reject Unicode control/format/surrogate/private-use/unassigned characters plus ambiguous
  non-ASCII whitespace, including line and paragraph separators, in every
  supplied evidence/policy text field and every JSON/Markdown-rendered report field;
  preserve ordinary international text unchanged.
- Bind baseline and candidate lineage by exact `release.name`, blocking
  mismatches with deterministic `RELEASE.NAME_MISMATCH` evidence for both
  names.
- Fail closed when a baseline-pinned interface loses valid candidate contract
  evidence, with canonical SHA-256 validation and explicit
  `INTERFACE.MISSING_CONTRACT_EVIDENCE` reporting.
- Reject empty compatibility declarations and prevent empty baseline versions
  from acting as compatibility evidence.
- Remove excepted `AUTHORITY.PRIVILEGE_CONTRACTION` deltas from effective
  `privilege_contractions` usage before evaluating risk budgets.

## [0.1.0] - 2026-07-23

### Added

- Deterministic `ota-evidence/v1` baseline/candidate comparison.
- SBOM dependency and license drift rules with risk budgets.
- Caller-supplied signed-manifest status and artifact-digest checks.
- Interface removal and compatibility checks.
- Authority expansion and contraction reporting.
- Rollback status, completeness, and artifact-binding rules.
- Approved exception matching with explicit expiry evaluation.
- Stable JSON and Markdown reports and pass/warn/block exit codes.
- Standard-library CLI, fixtures, tests, and cross-platform CI.
