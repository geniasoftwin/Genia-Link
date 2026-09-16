# GNP/1 Milestone 1 — Device Identity

Status: implementation checkpoint on top of Genia Link v0.3.1 RC4.

## Goal

Make the already existing persistent Genia Link installation identity an explicit shared Core contract used by both platform implementations, without changing the proven RC4 wire protocol.

## Identity rule

`DeviceId` identifies one installed Genia Link instance. It is generated once when the local cryptographic identity is first created and remains stable while that app identity/data remains present. A clean reinstall or explicit identity reset creates a new identity and therefore a new `DeviceId`.

The ID is not derived from IP, MAC address, computer/phone name, serial number, Android ID, or other hardware identifiers.

## Existing platform persistence retained

- Windows: `identity.json` stores `DeviceId` + CNG key name; the private ECDH P-256 key remains non-exportable in Windows CNG.
- Android: app-private `identity.json` stores `DeviceId` + Keystore alias; the private ECDH P-256 key remains non-exportable in Android Keystore.
- If the stored metadata/key is valid, the existing `DeviceId` is reused.
- If identity metadata/key material is missing or invalid, the platform rotates to a new cryptographic identity and a new `DeviceId`.

## M1 code change

`GeniaLink.Core.Identity.IDeviceIdentity` now defines the common identity surface required by pairing and trusted sessions:

- `DeviceId`
- `DeviceName`
- pairing peer projection
- public-key fingerprint
- ECDH shared-key derivation

Both `LocalIdentity` (Windows) and `AndroidLocalIdentity` implement this shared Core contract. Platform-specific secure key handling stays outside Core.

Private application fields intentionally keep their concrete platform identity types (`LocalIdentity` / `AndroidLocalIdentity`) to satisfy .NET analyzer CA1859 under `TreatWarningsAsErrors`. The shared M1 boundary is the interface implemented by both platform identity classes; no wire or persistence behavior is changed by this analyzer-compatible choice.

## Compatibility boundary

Milestone 1 intentionally does **not** change:

- `ProtocolConstants.Version` (still v3)
- UDP discovery packet format
- pairing packet format
- trusted-session handshake format
- transfer packet format
- ports
- trusted-device persistence format
- user-visible pairing/transfer behavior

This means existing RC4 peers remain wire-compatible during M1.

## Verification

`GeniaLink.SelfTest` contains a Core contract check that verifies the same `DeviceId`/`DeviceName` are projected into pairing identity. `SecurityCheck.ps1` also guards that both platform identity implementations continue to implement the Core contract while retaining their native secure key stores.

For the four-device lab (PC, notebook, two Android phones), the startup log prints `Local Device ID: <guid>`. Record each Device ID and fingerprint before restart, then verify the same device remains the same trusted peer after app restart, OS restart, sleep/wake, and DHCP/IP change. Do not reinstall during persistence tests; reinstall is a separate test and should produce a new identity.
