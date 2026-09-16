# Security Policy

## Reporting a vulnerability

Please do **not** publish exploit details, private keys, credentials, real device identifiers, or other sensitive material in a public issue.

Preferred reporting path:

1. Use GitHub private vulnerability reporting if it is enabled for this repository.
2. If private reporting is unavailable, open a minimal public issue asking for a private security contact. Do not include exploit details or secrets in that issue.

When possible, include the affected Genia Link version/build, platform, concise reproduction steps, expected vs. observed behavior, and the security impact.

## Scope

Reports concerning pairing, device identity, signing-key continuity, discovery authenticity/replay handling, trusted-session authorization, encrypted transfer framing, resume state, path confinement, lifecycle/revocation state, or authenticated capability assertions are especially relevant.

Third-party platform/framework issues should identify the upstream component and version when known.

## Sensitive material

Never attach production signing keys, keystores, PFX/P12 files, private certificates, access tokens, passwords, or real user data to a report.

## Implementation notes

Technical security notes for the current development snapshot are available in [docs/SECURITY_IMPLEMENTATION.md](docs/SECURITY_IMPLEMENTATION.md).
