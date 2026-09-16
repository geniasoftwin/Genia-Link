# GNP/1 Milestone 2.1 — Signing Identity

Status: implementation checkpoint on top of the verified Genia Link v0.3.1 RC4 + GNP/1 M1 Device Identity base.

## Goal

Give every existing Genia Link installation identity a separate ECDSA P-256 signing key so future GNP messages can prove which installed device identity created them.

Milestone 2.1 is intentionally local-only. It creates, stores, signs, verifies, and self-tests the signing identity, but it does not put Identity v2 or signatures on the RC4 wire protocol yet.

## Migration rule

The verified M1 `DeviceId` and ECDH P-256 agreement key are preserved.

When an M1 installation starts M2.1 for the first time:

1. the existing `DeviceId` is loaded unchanged;
2. the existing ECDH key is loaded unchanged;
3. a new, separate ECDSA P-256 signing key is created in platform secure storage;
4. `identity.json` is upgraded with signing-key metadata;
5. `KeyGeneration` starts at `1`;
6. the startup log prints the public `SigningKeyId`.

If only the signing key is missing or invalid later, the signing key is rotated and `KeyGeneration` is incremented. The `DeviceId` and valid ECDH identity are not intentionally changed by a signing-key rotation.

A full app identity reset/reinstall remains a different event and may create a new `DeviceId` as defined by M1.

## Key separation

M2.1 uses two different EC P-256 key pairs with different purposes:

- ECDH P-256: key agreement for the existing pairing/trusted-session path;
- ECDSA P-256: signatures for future GNP authenticated identity messages.

The same private key is never reused for agreement and signing.

## Platform storage

### Windows

- provider: Microsoft Software Key Storage Provider (CNG);
- agreement key: `ECDiffieHellmanP256`, non-exportable;
- signing key: `ECDsaP256`, `CngKeyUsages.Signing`, non-exportable;
- private signing key is never written to JSON.

### Android

- provider: Android Keystore;
- agreement key purpose: `AgreeKey`;
- signing key purposes: `Sign | Verify`;
- signing digest: SHA-256;
- private signing key is never written to JSON or exported.

## Core contract

`IDeviceSigningIdentity : IDeviceIdentity` adds the M2 surface without removing the M1 contract:

- `IdentityVersion`
- `KeyGeneration`
- `CreatedAtUtc`
- `DeviceKind`
- `DisplayName`
- `SigningKeyId`
- `ExportSigningPublicKey()`
- `Sign(...)`
- `VerifySignature(...)`
- `ToDeviceIdentityV2()`

`DeviceIdentityV2` is a public, transport-neutral snapshot. It contains public identity data only.

## Signing format

- algorithm: ECDSA P-256;
- digest: SHA-256;
- public-key encoding: SubjectPublicKeyInfo (SPKI);
- signature encoding: RFC 3279 DER sequence;
- `SigningKeyId`: uppercase hexadecimal SHA-256 fingerprint of the SPKI signing public key.

This explicit format is chosen so Windows/.NET and Android/Java signatures can be verified by the same Core logic.

## Compatibility boundary

M2.1 intentionally does **not** change:

- `ProtocolConstants.Version` (still v3);
- UDP discovery packet format;
- pairing packet format;
- trusted-session handshake format;
- transfer packet format;
- ports;
- trusted-device store format;
- current transfer UI/behavior.

The new signing public key is not transmitted by RC4 yet.

## Self-tests and source guards

`GeniaLink.SelfTest` verifies that:

- a valid ECDSA P-256/SHA-256 DER signature verifies;
- changing one byte invalidates the signature;
- `SigningKeyId` is deterministic;
- the Identity v2 snapshot binds its key ID to the signing public key.

`SecurityCheck.ps1` additionally guards:

- separate M2 Core contract/model/crypto files;
- Windows CNG ECDSA P-256 non-exportable signing key;
- Android Keystore ECDSA P-256 signing key with SHA-256;
- absence of known private-key export APIs;
- protocol version remains v3 through the existing protocol checks.

## Four-device acceptance test

Install/update M2.1 over the existing M1 installation. Do **not** uninstall the app for this migration test.

For each device, record:

- `Local Device ID`;
- `GNP/1 M2 Signing Key ID`;
- signing key generation.

Expected first M2.1 start:

- `Local Device ID` equals the M1 value recorded before the update;
- each device has its own signing key ID;
- generation is `1`.

Then fully restart Genia Link and reboot at least one Windows and one Android device. Expected:

- Device ID unchanged;
- Signing Key ID unchanged;
- generation unchanged.

File discovery, pairing, trusted sessions, remote folder operations, and file transfer should continue to behave as in RC4 because M2.1 does not alter the wire protocol.

## Next step

After M2.1 passes on all four devices, M2.2 can define the first signed GNP Identity v2 message/envelope and the compatibility rules for exchanging the signing public key without breaking existing RC4 peers.
