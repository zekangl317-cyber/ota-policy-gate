# Contributing

Contributions should preserve the tool's narrow evidence-orchestration boundary
and deterministic output contract.

## Development setup

Python 3.11 or newer is sufficient; runtime dependencies are not required.

```powershell
$env:PYTHONPATH = "src"
$env:PYTHONDONTWRITEBYTECODE = "1"
python -B -m unittest discover -s tests -v
python -B -m ota_policy_gate --help
```

An optional editable install is:

```powershell
python -m pip install --no-build-isolation -e .
```

## Change expectations

- Add behavior-level tests through the public API or CLI.
- Exercise at least one negative path for new evidence types.
- Keep rule IDs stable; document any new ID and severity.
- Do not read the current clock. Add an explicit input when time affects policy.
- Keep JSON ordering and Markdown rendering deterministic.
- Do not claim to verify signatures or fabricate cryptographic evidence.
- Update the architecture document, fixtures, and changelog for schema changes.

Run the complete test suite before submitting a change. Generated reports,
virtual environments, caches, wheels, and editable-install metadata must not be
committed.

