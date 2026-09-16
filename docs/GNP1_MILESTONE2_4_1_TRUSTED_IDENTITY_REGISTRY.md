# GNP/1 Milestone 2.4.1 — Trusted Identity Registry

Status: development checkpoint on top of the real-device verified M2.3 `fix3` baseline.

## Goal

M2.3 already authenticates the persistent Device Identity v2 signing public key through the pre-existing trusted ECDH relationship and stores the current binding inside `trusted-devices.json`.

M2.4.1 adds a separate local **Trusted Identity Registry** so Genia Link can retain a durable identity history without changing the working pairing/transfer path.

The key design rule is:

> Updating Genia Link is not a new device and must not create a new cryptographic identity.

The registry therefore preserves the already trusted relationship and gives future GNP milestones a stable place to build trust grants, revocation, controlled key rotation and authenticated session identity.

## Compatibility boundary

M2.4.1 intentionally does **not** change:

- `ProtocolConstants.Version = 3`;
- TCP 47500 transfer protocol;
- TCP 47501 pairing protocol;
- UDP 47502 `GLD2` + `GLS1` discovery;
- TCP 47503 M2.3 authenticated signing-identity binding;
- `TrustedSessionHandshake`;
- `SecureChannel`;
- the existing Device ID;
- the platform ECDH agreement key;
- the platform ECDSA signing key;
- the existing `trusted-devices.json` pairing database format.

An M2.4.1 installation can therefore be updated in place over the tested M2.3 `fix3` state without asking the user to pair devices again.

## New local registry

M2.4.1 adds:

`trusted-identities.json`

The file is local to the same application data directory as the existing trusted-device store.

Each registry entry contains:

- persistent `DeviceId`;
- safe current device name;
- SHA-256 `PairingKeyId` of the already trusted ECDH public key;
- `FirstTrustedAtUtc`;
- `LastAuthenticatedAtUtc`;
- registry state (`Trusted`, reserved `Changed`, reserved `Revoked`);
- current authenticated signing identity version;
- current signing-key generation;
- current `SigningKeyId`;
- current ECDSA P-256 public key;
- first bound / last verified timestamps for that signing key;
- bounded history of retired signing keys.

No private ECDH or ECDSA key is written to the registry.

## Pairing anchor

The registry does not invent a new trust source.

The existing paired ECDH public key remains the trust anchor for migration from M2.3. M2.4.1 derives a full SHA-256 `PairingKeyId` from that validated public key and pins it to the registry record.

If an explicit new pairing replaces the ECDH public key for the same Device ID, the registry treats that as a new pairing trust anchor:

- the registry pairing fingerprint is replaced;
- the old current signing binding is cleared unless the new trusted-device record already contains a valid authenticated binding;
- previous signing-key history is cleared for the new trust anchor.

This prevents signing history from one pairing trust relationship from being silently inherited by another.

## Automatic migration from M2.3

On startup both Windows and Android:

1. load the unchanged `trusted-devices.json` database;
2. validate the stored paired ECDH public key using the existing pairing rules;
3. validate any stored M2.3 signing binding;
4. create or reconcile the corresponding `trusted-identities.json` entry;
5. keep all existing Device IDs, pairings and signing identities unchanged;
6. when `trusted-devices.json` loaded successfully, remove registry records for devices that are no longer paired.

No user confirmation and no repeat pairing are required for a valid M2.3 `fix3` installation.

The active M2.3 trusted-device database remains the authority for whether a peer is currently trusted. An old registry entry therefore cannot resurrect a device that the user removed. If the trusted-device database itself is unreadable, orphan pruning is skipped so registry history is not destroyed merely because of a corrupted legacy file.

If registry migration itself cannot be persisted, the application logs the M2.4.1 failure but keeps the already working M2.3 trust relationship. The registry is deliberately not allowed to turn a local storage problem into a false identity-change warning or a forced re-pair.

## Authenticated signing-key updates

The existing M2.3 binding rules remain the authority for accepting a signing identity:

- no stored signing key -> bind generation 1 or newer;
- same signing key -> preserve it; lower generation is rejected;
- different signing key -> require a strictly higher generation;
- different key at the same/lower generation -> reject.

After the M2.3 store accepts an authenticated binding, M2.4.1 mirrors that result into the registry.

When a higher-generation key is accepted:

1. the previous current signing key is moved into bounded history as `Retired`;
2. its identity version, generation, key fingerprint, public key and trust timestamps are retained;
3. the new key becomes current;
4. no UDP discovery packet alone can perform this operation.

The current implementation keeps at most 32 retired signing-key history records per trusted identity.

## Authenticated-contact timestamp

When an already trusted session successfully refreshes the persisted LAN endpoint, the registry also updates `LastAuthenticatedAtUtc`.

UDP discovery does not update this timestamp because discovery is not a trusted-session proof.

## Persistence and recovery

The registry is size bounded to 1 MiB and 1024 trusted identities.

Writes use:

1. serialization to `trusted-identities.json.tmp`;
2. preservation of the previous complete primary as `trusted-identities.json.bak`;
3. replacement of the primary with the completed temp file;
4. cleanup of a stale temp file when possible.

On startup:

- a valid primary is used normally;
- if the primary is invalid but the backup is valid, the backup is loaded and copied back over the primary;
- if neither is usable, the registry starts empty and can be rebuilt from the still-valid M2.3 trusted-device database.

The backup is a local crash/corruption recovery copy; it is not a separate cryptographic trust authority.

## Registry validation

A loaded registry is rejected if it contains, among other things:

- an empty Device ID;
- an invalid/oversized device name;
- an invalid SHA-256 pairing/signing fingerprint;
- an unsupported schema version;
- more than the bounded number of identities/history entries;
- an incomplete signing identity;
- an invalid ECDSA P-256 public key;
- a `SigningKeyId` that does not match SHA-256 of the stored signing public key;
- duplicate Device IDs;
- invalid registry/history state values.

## Self-test coverage

`GeniaLink.SelfTest` now checks that M2.4.1:

- migrates an existing trusted pairing/signing identity;
- preserves Device ID and pairing-key fingerprint;
- survives reload/restart;
- rotates to a higher authenticated signing generation;
- stores the retired signing key in history;
- rejects a different signing key at the same generation;
- writes a `.bak` file on later updates;
- recovers from a corrupted primary using the backup;
- clears signing binding/history when an explicit pairing trust anchor changes.

`SecurityCheck.ps1` adds the expected success line:

`GNP/1 M2.4.1 TRUSTED IDENTITY REGISTRY CHECK PASSED`

`SecurityCheck-Android.ps1` runs the same core/security gate before the Android-specific checks.

## Real-device acceptance test

Start from the four-device M2.3 `fix3` installations that already passed real tests.

### 1. Update in place

Replace the app build without clearing app data.

Expected:

- same Local Device ID;
- same GNP/1 M2 Signing Key ID;
- same signing-key generation;
- all previous devices still trusted;
- no false `Ключ изменился` state;
- no pairing prompt caused by the update.

### 2. Registry startup

Each node should log a line similar to:

`GNP/1 M2.4.1 Trusted Identity Registry active: 3 trusted identity record(s).`

The exact count depends on how many peers are paired on that device.

### 3. File creation

After startup, verify that the application data directory contains:

`trusted-identities.json`

Existing `trusted-devices.json` must remain present and readable.

### 4. Restart/reboot

Restart Genia Link on all devices and reboot at least one Windows and one Android device.

Expected:

- Device ID unchanged;
- signing key unchanged;
- pairings unchanged;
- M2.3 authenticated signing bindings unchanged;
- M2.4.1 registry loads without migration conflicts.

### 5. Transfer regression

Repeat:

- Windows <-> Windows;
- Windows <-> Android;
- Android <-> Android;
- sleeping trusted endpoint fallback;
- browse / preview / reverse download;
- Android Always Ready separately.

The transfer wire format and authentication behavior must be identical to M2.3.

### 6. Security gate

Run:

```powershell
.\scripts\SecurityCheck-Android.ps1
```

Expected lines include:

- `GNP/1 M2.3 TRUSTED SIGNING IDENTITY BINDING CHECK PASSED`
- `GNP/1 M2.4.1 TRUSTED IDENTITY REGISTRY CHECK PASSED`
- final self-test/security success lines.

## Next boundary

M2.4.1 deliberately stops at a durable local trusted-identity registry.

A later milestone can use this registry to define signed trust records such as `TrustGrant` / `TrustRevoke` and explicit controlled signing-key rotation semantics. Those future operations should be added as new authenticated GNP trust behavior rather than retroactively changing the stable M2.3 pairing path.
