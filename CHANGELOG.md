# Changelog

All notable public source snapshots of Genia Link will be documented here.

## Unreleased

### GNP/1 M2.7 — Service Concurrency & Device UI — 2026-09-20

- Added bounded file-level concurrency without changing the transfer wire format: up to three outgoing trusted sessions per peer and up to four concurrent incoming trusted sessions.
- Preserved independent trusted handshake, secure channel, resume state and SHA-256 verification for every file session.
- Added per-peer scheduling so separate Send To requests can share the same bounded session pool; duplicate source files are serialized to avoid resume-state races.
- Added per-file transfer activity rows and a compact completed-transfer history instead of multiplexing all concurrent progress into one progress bar.
- Added local per-device aliases keyed by stable Device ID while preserving the original advertised device name and all cryptographic identity/trust state.
- Added authenticated role presentation and live role/profile refresh from accepted capability revisions.
- Added device search and dynamic filters generated only from states, authenticated roles and authenticated services that are actually present.
- Added a service-ready selected-device UI with common Files access and a dynamic Actions menu; future Print/Scan/Chat entries are intentionally not shown until real authenticated services exist.
- Moved diagnostics out of the main work surface into a dedicated menu-only window with copy/clear controls and wrapped log lines.
- Added Windows crash diagnostics and safer Explorer launching for completed transfer history.
- Added a Windows Firewall diagnostic note for rebuilt/moved executables that may need a new Private-network allowance for inbound TCP 47500.
- Live testing confirmed true simultaneous Windows → Android and Android → Windows transfers, slot refill behavior, successful integrity verification, and immediate authenticated role updates in the UI.
- Protocol version remains 3; pairing, Device IDs, signing keys and the M2.6.2 signed-capability advertisement format remain unchanged.
- No release or tag is created for this development checkpoint.

### M2.6.2 Android Keystore validation — 2026-09-18

- Fixed Android ECDSA signing to use the existing non-exportable Android Keystore `PrivateKeyEntry`.
- Confirmed live M2.6.2 signed capability advertisement from Android without legacy GLD2 fallback.
- Confirmed authenticated Android capability acceptance and automatic `Client` profile resolution on Windows.
- Confirmed Windows Server capability revision advertisement is verified on Android.
- Existing Device IDs, pairings and signing-key generations remain unchanged.
- No release or tag is created for this development checkpoint.

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
