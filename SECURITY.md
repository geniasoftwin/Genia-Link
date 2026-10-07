## M2.8.4.5 Cancel / Retry security checkpoint — 2026-10-06

The physically validated M2.8.4.5 development checkpoint keeps the existing local-only trust boundary and adds authenticated, fail-closed print cancellation.

Cancel ownership is bound to the accepted JobId and authenticated remote DeviceId. Before Windows spooler submission, cancellation may stop local preparation; after submission, cancellation targets only the exact correlated Genia Link job. If the exact spooler job can no longer be proven, cancellation is reported as **not confirmed** and Retry is suppressed to avoid duplicate printing.

Office-document preparation remains cancellation-aware, including a bounded 3000 ms pre-spool window after preparation completes. Retry is explicit, preserves the selected document/settings, and uses a new JobId.

The checkpoint retains authenticated GNP/1 sessions, PrinterGateway capability enforcement, SHA-256 staging, bounded print payloads and the conservative lifecycle behavior introduced in M2.8.4.4. It does not add HTTP/cloud/analytics, queue-wide cancellation or an unauthenticated print listener.

See the [M2.8.4.5 checkpoint](docs/GNP1_MILESTONE2_8_4_5_CANCEL_RETRY.md), [architecture overview](docs/ARCHITECTURE.md) and [threat model](docs/THREAT_MODEL.md).

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
