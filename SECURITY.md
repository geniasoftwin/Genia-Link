# Security Policy

## Reporting a vulnerability

Please do **not** publish exploit details, private keys, credentials, device identifiers, or other sensitive material in a public issue.

Preferred reporting path:

1. Use GitHub's private **Report a vulnerability** / private vulnerability reporting feature if it is enabled for this repository.
2. If private reporting is not available, open a minimal public issue stating that you need a private security contact. Do not include reproduction secrets or exploit details in that issue.

Please include, when possible:

- affected Genia Link version/build;
- affected platform (Windows/Android);
- a concise description of the issue;
- reproduction steps that do not expose third-party secrets;
- expected vs. observed behavior;
- security impact;
- whether the issue is already public.

## Scope

Security reports concerning pairing, device identity, discovery authenticity, encrypted transfer, resume state, path handling, trusted-device state, or local-network authorization are especially relevant.

Third-party operating-system, framework, or dependency vulnerabilities should also identify the upstream component and version when known.

## Sensitive material

Never attach production signing keys, keystores, PFX/P12 files, private certificates, access tokens, passwords, or real user data to a report.
