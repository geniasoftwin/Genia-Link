# Genia Link v0.3.1 RC4 / GNP/1 M2.6.2

First public source snapshot of Genia Link.

## Status

This is a **pre-release source checkpoint**, not a stable release. It represents the v0.3.1 RC4 line with GNP/1 M2.6.2 Authenticated Capabilities.

## Highlights

- Windows and Android clients sharing the protocol/core implementation.
- Direct trusted device-to-device file transfer on a local IPv4 network.
- Automatic local discovery.
- Explicit SAS pairing and persistent trusted device identity.
- ECDH P-256 key agreement with per-session keys.
- AES-256-GCM protected transfer frames.
- SHA-256 file verification and resumable partial transfers.
- Trusted Identity Registry with signing-key binding and continuity-verified key rotation.
- Replay-hardened signed identity assertions.
- Active / Retired / Revoked trusted-identity lifecycle.
- GNP/1 M2.6.2 authenticated capability advertisement through the `GLC1` envelope.
- Automatic Client / Server / Relay / Backup / Custom profile resolution from local capability sets.
- Windows Send To integration and Android share workflow.
- Optional Android Always Ready mode for long-idle availability.
- Offline self-tests and PowerShell security-check scripts included.

## Compatibility notes

For the M2.6.2 checkpoint:

- `ProtocolConstants.Version` remains 3.
- Pairing protocol is unchanged.
- Transfer protocol is unchanged.
- TCP ports are unchanged.
- Existing trusted devices do not require re-pairing.
- Device ID, ECDH pairing identity, signing identity, key history, TrustRelationshipId and lifecycle are preserved.
- Older peers ignore `GLC1` and continue through the compatibility discovery envelopes.

## Build

The source targets .NET 10. Windows requires the Windows desktop toolchain; Android requires the .NET for Android workload.

Before producing binaries, run the project security/build checks on the intended Windows/.NET/Android toolchain.

## Important

- No binaries are attached to this source checkpoint by default.
- This repository is source-available for inspection and is **not** released under an open-source license.
- Project-owned material remains All Rights Reserved unless explicitly stated otherwise.
- Do not publish private keys, signing material, credentials, trusted-device runtime data or real device identifiers in issues or reports.

## Documentation

- `README.md`
- `README.ru.md`
- `CHANGELOG.md`
- `docs/GNP1_MILESTONE2_6_2_AUTHENTICATED_CAPABILITIES.md`
- `docs/RC4_FINAL_TEST.md`
- `docs/SECURITY_IMPLEMENTATION.md`
- `SECURITY.md`
