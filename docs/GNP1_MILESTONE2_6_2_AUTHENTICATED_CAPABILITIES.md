# GNP/1 M2.6.2 — Authenticated Capability Advertisement

## Goal

M2.6.2 turns the M2.6.1 local capability model into an authenticated peer assertion without turning capabilities into authorization. A device may announce what functions it supports, but a receiver accepts that capability state only after the announcement is cryptographically bound to the already trusted Device ID, ECDH pairing anchor and current pinned ECDSA signing identity.

This checkpoint also makes the capability set authoritative for the local user-facing role profile. Exact preset sets resolve automatically to Client, Server, Relay or Backup; every other valid combination resolves to Custom.

## GLC1 additive discovery envelope

M2.6.2 adds `GLC1` and keeps protocol version 3. A current node sends discovery in this order:

1. `GLC1` — signed identity + capability assertion;
2. `GLS2` — M2.5.3 replay-protected identity compatibility;
3. `GLS1` — M2.2 signed identity compatibility;
4. `GLD2` — legacy RC4 discovery compatibility.

A current receiver prefers `GLC1` for the same Device ID during the normal discovery-expiry window and suppresses immediate downgrade to GLS2/GLS1/GLD2.

`GLC1` signs these fields in network byte order:

- magic `GLC1`;
- protocol version;
- identity version;
- Device ID;
- transfer port;
- pairing port;
- DeviceKind;
- signing-key generation;
- M2.5.3 `IdentityRevision` (Int64, positive);
- M2.6.2 `CapabilityRevision` (Int64, positive);
- capability bitset (Int64; only current known bits are accepted);
- bounded UTF-8 device name;
- existing ECDH pairing-public-key fingerprint;
- ECDSA P-256 signing public key;
- DER ECDSA/SHA-256 signature over all preceding signed fields.

The public `SigningKeyId` is still derived from the verified signing public key; it is not trusted merely because it appears on the LAN.

## Separate CapabilityRevision

Capabilities can change while Device ID, name and signing key remain unchanged. Reusing `IdentityRevision` would therefore allow a historical but valid capability packet to roll a peer back to an older feature set.

Each installation now persists `capability-assertion-revision.json` with backup recovery. The revision:

- remains unchanged while the capability set and signing generation/key are unchanged;
- advances exactly once when the capability set changes;
- advances when the current signing key/generation changes;
- initializes from a high time-based recovery baseline if the revision file is missing/corrupt.

The capability revision is independent from `IdentityRevision`.

## Trust acceptance rule

A parsed `GLC1` is only a valid signature proof. It is not yet an authenticated trusted capability state.

Windows and Android apply it through the existing trusted-device validation path. The receiver requires all of the following:

- existing trusted Device ID;
- lifecycle `Active`;
- registry state `Trusted`;
- matching ECDH pairing key/fingerprint;
- matching current signing identity version;
- matching current signing-key generation;
- matching pinned `SigningKeyId`;
- positive `IdentityRevision`;
- positive `CapabilityRevision`;
- known capability bits only;
- mandatory Trusted Discovery + Trusted Transport core bits.

Only then is the capability assertion stored in Trusted Identity Registry schema v5.

Schema v5 adds:

- `VerifiedCapabilities`;
- `LastAcceptedCapabilityRevision`;
- `CapabilitiesLastVerifiedAtUtc`.

For a trusted identity:

- `CapabilityRevision < LastAcceptedCapabilityRevision` is rejected as replay/rollback;
- equal revision with a different capability set is rejected as conflict;
- equal revision with the same set may refresh authenticated contact state;
- a higher valid revision replaces the authenticated capability set.

Pre-v5 registries migrate with no authenticated capability state and require a fresh valid GLC1 before capabilities are trusted. Explicit pairing-trust replacement clears the old authenticated capability state. A continuity-proven signing-key rotation also clears the previous capability assertion: device trust survives, but the new key must authenticate its capability set again.

## Capability advertisement is not authorization

A peer saying `Relay`, `Backup`, `PrinterGateway` or another capability does not grant it network authority. M2.6.2 records a trusted statement of supported functionality only.

Administrative permissions, protected service authorization and network-wide policy remain future checkpoints. Local `Active / Retired / Revoked` lifecycle remains authoritative.

## Automatic profile resolution

The role is now a presentation/preset layer over the capability set:

- exact Client preset -> Client;
- exact Server preset -> Server;
- exact Relay preset -> Relay;
- exact Backup preset -> Backup;
- every other valid set -> Custom.

In Windows Settings the user may select a preset to populate its capability set. If the user manually changes an optional capability and the resulting set no longer matches a preset, the profile changes to Custom. If later checkbox changes recreate an exact preset, the corresponding profile is selected automatically.

Trusted Discovery and Trusted Transport remain mandatory core capabilities. In Custom mode infrastructure flags such as Background Availability are no longer locked unless required by the currently resolved preset.

## Android

Android participates in M2.6.2 advertisement using the current Client capability preset. Android does not yet expose the Windows role/capability editor; its advertised set is generated by the application and protected by the same persistent CapabilityRevision mechanism.

## Compatibility

- `ProtocolConstants.Version` remains 3.
- Pairing protocol is unchanged.
- Transfer protocol is unchanged.
- TCP ports are unchanged.
- Existing trusted devices do not require re-pairing.
- Device ID, ECDH pairing identity, signing identity, key history, TrustRelationshipId and lifecycle are not recreated.
- Older peers ignore `GLC1` and continue through GLS2/GLS1/GLD2.

## Acceptance test

1. Upgrade all test devices from M2.6.1 without deleting app data.
2. Confirm Device IDs, pairings and signing keys are unchanged.
3. On Windows open Settings -> Role and functions.
4. Select Client, Server, Relay and Backup; each preset must populate the expected checkboxes.
5. Change one optional checkbox; the profile must become Custom.
6. Recreate an exact preset using checkboxes; the profile must switch automatically to that preset.
7. In Custom verify Background Availability is editable; Trusted Discovery and Trusted Transport remain checked/locked.
8. Save a changed capability set. Local services must restart and the log must show a new M2.6.2 capability revision/advertisement.
9. On an already trusted M2.6.2 peer, the log must show authenticated capabilities accepted with the resolved profile.
10. Restart both peers. The capability set/profile must restore without new pairing.
11. Run `scripts\SecurityCheck-Android.ps1` and require all build/analyzer/self-tests to pass.
12. Regression-test Windows <-> Windows, Windows <-> Android and Android <-> Android transfer/discovery after the new GLC1 envelope is enabled.

## Android Keystore signing compatibility fix

Android ECDSA signing now retrieves the existing non-exportable key through
`KeyStore.GetEntry(alias, null)` and `KeyStore.PrivateKeyEntry.PrivateKey`.
This follows the Android Keystore signing model and avoids relying on a managed
`is IPrivateKey` check over the object returned by `GetKey()`, which can fail on
real Android runtimes even when the Keystore entry itself is a valid private key.

The change does **not** replace the key, Device ID, key generation, pairing
anchor, or Trusted Identity Registry records. Existing trusted relationships
remain valid. Android can now publish GNP/1 signed discovery and M2.6.2 signed
capability advertisements instead of falling back to legacy GLD2 discovery.

## Live validation status — 2026-09-18

Field testing on Windows and multiple Android devices confirmed:

- Android publishes GNP/1 M2.6.2 signed capability advertisements after the Keystore fix.
- Windows verifies and accepts authenticated capability advertisements from trusted Android peers.
- The Android Client capability set resolves automatically to the `Client` profile on Windows.
- Android verifies Windows M2.6.2 capability advertisements, including a changed Server capability revision.
- Existing Device IDs, trusted pairings and signing-key generations remained intact across the update.
- Encrypted file transfer continued to work in both directions between Windows and Android peers.

Android-to-Android authenticated capability acceptance remains a final explicit
log checkpoint before M2.6.2 is considered fully closed.

