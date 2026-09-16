# Changelog

All notable public source snapshots of Genia Link will be documented here.

## v0.3.1 RC4 / GNP/1 M2.6.2 — 2026-09-16

Initial public source snapshot of Genia Link.

### Highlights

- Windows and Android clients with a shared protocol/core implementation.
- Local IPv4 device discovery and direct device-to-device transfer.
- Explicit SAS pairing and persistent trusted device identity.
- ECDH P-256 key agreement with per-session keys.
- AES-256-GCM protected transfer frames.
- SHA-256 file verification and resumable partial transfers.
- Trusted Identity Registry with signing-key binding and continuity-verified key rotation.
- Replay-hardened signed identity assertions.
- Active / Retired / Revoked trusted-identity lifecycle.
- GNP/1 M2.6.2 authenticated capability advertisement (`GLC1`).
- Automatic role/profile resolution from authenticated capability sets.
- Windows Send To integration and Android share workflow.
- Optional Android Always Ready mode for long-idle availability.
- Offline self-tests and PowerShell security-check scripts included in the source tree.

### Notes

- This is a release-candidate / protocol-development checkpoint, not a stable release.
- The repository is source-available for inspection and is not released under an open-source license.
- No release binaries are included with this source snapshot.
- Protocol, packaging, UI and compatibility details may change before a stable release.

### Documentation

- `docs/GNP1_MILESTONE2_6_2_AUTHENTICATED_CAPABILITIES.md`
- `docs/RC4_FINAL_TEST.md`
- `docs/SECURITY_IMPLEMENTATION.md`
- `docs/PROTOCOL.md`
