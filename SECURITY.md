## M2.8.4.4 fix23 security checkpoint — 2026-10-03

The physically validated fix23 development package keeps the existing local-only trust boundary: authenticated GNP/1 sessions, trusted PrinterGateway capability enforcement, SHA-256 staging, bounded print payloads and no HTTP/cloud/analytics path.

Print lifecycle observation is read-only. System.Printing, `GetPrinter(PRINTER_INFO_6)`, bounded `EnumJobs`, spooler change notifications and Bidi status probing are used only to observe local Windows state. Genia Link does not issue Bidi `Set`, `SetPrinter`, `SetJob` or automatic cancellation as part of M2.8.4.4.

When the installed driver cannot prove physical completion, Genia Link fails conservative rather than claiming success. The tested Samsung SCX-4300 can remove a job from the Windows queue before physical paper handling is known, so the client reports that the job was handed to the printer while physical status is unavailable.

fix23 changes Android foreground-notification ownership/cleanup only; it does not weaken trusted transport, printer authorization, staging limits or lifecycle authentication.

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
