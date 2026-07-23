# Security policy

## Supported versions

Security fixes are applied to the latest released minor version. The current
development line is 0.1.x.

## Reporting a vulnerability

Use the repository host's private security-advisory mechanism when available.
Do not include exploit details, real signing material, production SBOMs,
device credentials, or sensitive release evidence in a public issue. Include a
minimal synthetic reproducer, affected version, impact, and suggested
mitigation.

## Security boundary

`ota-policy-gate` treats every JSON field as untrusted input and does not execute
commands, load plugins, access the network, or verify signatures. Output paths
are explicitly selected by the caller. The tool cannot establish evidence
provenance: a `verified` status is only metadata supplied by the caller. Release
systems must authenticate evidence producers, protect policy files and approved
exceptions, run an actual signature verifier, and archive the original evidence
alongside the decision.

Malformed input should produce exit code 64 rather than a release decision. A
logic error that incorrectly passes a release, mishandles exception expiry, or
causes nondeterministic decisions is security-relevant.

