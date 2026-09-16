# GNP/1 Milestone 2.5 — Trusted Identity State Management

## Checkpoint 1: Authenticated Rename Propagation

M2.5 begins the trusted-identity lifecycle work with a deliberately narrow first rule: a device may change its human-readable name without becoming a new cryptographic identity.

Canonical example:

`DESKTOP-TOFLGGG` → `GENIABOOK`

The rename must preserve:

- persistent `DeviceId`;
- paired ECDH P-256 public key / `PairingKeyId`;
- current ECDSA P-256 signing key / `SigningKeyId`;
- signing `KeyGeneration`;
- existing trust relationship;
- signing-key rotation history;
- original `FirstTrustedAtUtc`.

No SAS re-pair is required when those anchors remain unchanged.

## Existing cryptographic evidence

M2.2 `GLS1` already signs the device name together with:

- `DeviceId`;
- protocol and identity version;
- transfer/pairing ports;
- `DeviceKind`;
- signing-key generation;
- ECDH public-key fingerprint;
- signing public key.

Windows `LocalIdentity` derives the current display name from `Environment.MachineName`. Therefore an OS rename causes the same persistent Device ID and keys to produce a new valid `GLS1` advertisement containing the new machine name.

M2.5 does not add a new wire packet for rename. It turns already-signed discovery data into a safe state transition only after it is matched against the locally trusted identity.

## Acceptance rule

A received name is eligible for automatic propagation only when all of the following are true:

1. the packet was parsed and cryptographically verified as `GLS1` / `SignedIdentityV2`;
2. `DeviceId` resolves to an existing trusted device;
3. the advertised ECDH fingerprint exactly matches the paired ECDH public key;
4. the advertised `SigningKeyId` exactly matches the currently trusted signing key;
5. identity version exactly matches the pinned current signing identity version;
6. signing-key generation exactly matches the pinned current generation;
7. the corresponding Trusted Identity Registry record exists and is in `Trusted` state;
8. the registry `PairingKeyId`, current signing key, identity version and generation match the trusted-device record;
9. the new name passes the existing bounded UTF-8 / unsafe-character validation.

Only then may `DeviceName` be replaced.

A self-signed advertisement from an unknown key is not enough. A valid signature under a different key is not enough. A stale lower generation is not enough. A mismatched ECDH fingerprint is not enough.

## Persistence behavior

When the rule succeeds:

- `trusted-devices.json` updates only `DeviceName`;
- `trusted-identities.json` records the same authenticated name and advances authenticated/verified timestamps;
- Device ID and all trust anchors are preserved;
- no signing-key history entry is created;
- no pairing prompt is shown.

The operation is idempotent. Repeated advertisements with the already stored name do not rewrite the trusted-device file.

The two existing local JSON stores remain separate files, so cross-file persistence is not a single filesystem transaction. The trusted-device record is updated first and the registry is mirrored immediately; normal startup reconciliation remains able to repair a registry write failure from the already authenticated trusted-device state.

## Windows flow

For a previously bound trusted peer:

1. receive and verify `GLS1`;
2. compare the signed identity metadata with local trust anchors;
3. persist the authenticated name if changed;
4. promote the current discovery entry to `AuthenticatedTrustedIdentityV2`;
5. skip redundant TCP 47503 binding when the exact signing identity is already pinned.

For a legitimate M2.4.2 key rotation, rename is not accepted merely because the new key self-signed discovery. TCP 47503 must first validate the key rotation continuity chain. After the new key becomes trusted, the already verified discovery packet may then authenticate the name under that newly trusted key.

## Android flow

The same rule runs in both places that keep trusted state:

- `MainActivity` UI store;
- `LocalAvailabilityService` background store.

The background service retains the latest verified discovery record long enough for a pending M2.3/M2.4.2 signing binding to complete. If a new signing generation is successfully authenticated, the latest signed discovery is re-evaluated against the newly trusted key so a simultaneous legitimate rename can propagate without requiring the UI to be open.

Expired discovery records and network-loss resets also clear that temporary latest-discovery cache.

## Rejected cases

Automatic rename is rejected when:

- discovery is legacy unsigned `GLD2` only;
- the Device ID is not trusted;
- ECDH fingerprint differs;
- signing key differs and has not yet passed authenticated rotation binding;
- signing generation is stale or inconsistent;
- registry state is not `Trusted`;
- registry/store trust anchors disagree;
- the name is malformed or unsafe.

Rejection preserves the existing trusted name and does not alter Device ID, keys or pairing state.

## Freshness boundary of checkpoint 1

`GLS1` authenticates the origin and contents of the advertised name, but the current M2.2 packet does not contain a signed monotonic name generation, boot/session nonce, or other persistent freshness value. Therefore checkpoint 1 authenticates **who is allowed to assert a name**, but it does not yet impose a total order on multiple historically valid names. A captured older valid `GLS1` could be replayed on the LAN and restore an older display name; it still cannot change `DeviceId`, pairing/signing keys, signing generation, or trust state.

The identity-name-history portion of M2.5 should close this remaining display-state replay class with a monotonic authenticated name revision (or equivalent challenge-bound current-name proof) before rename history is treated as irreversible lifecycle evidence.

## Self-test coverage

`GeniaLink.SelfTest` extends the Trusted Identity Registry test to verify that:

- `DESKTOP-TOFLGGG`-style rename to `GENIABOOK` is persisted under the current trusted signing identity;
- Device ID is unchanged;
- pairing key ID is unchanged;
- signing key ID and generation are unchanged;
- `FirstTrustedAtUtc` is unchanged;
- signing-key history is unchanged;
- a rename presented with a non-trusted signing key ID is rejected and leaves the trusted name intact.

## Real-device acceptance test

Recommended first M2.5 test:

1. start with two already paired M2.4.2 devices and record the Windows peer's Device ID, ECDH fingerprint, Signing Key ID and generation;
2. rename Windows from `DESKTOP-TOFLGGG` to `GENIABOOK` using the operating system;
3. restart Windows so `Environment.MachineName` reports the new name;
4. do **not** re-pair and do **not** rotate keys;
5. wait for signed discovery on the other peer;
6. verify the UI changes to `GENIABOOK`;
7. restart the observing peer and verify the sleeping trusted endpoint is still named `GENIABOOK`;
8. verify Device ID, ECDH fingerprint, Signing Key ID and generation are byte-for-byte/log-for-log unchanged;
9. transfer a file both directions without pairing confirmation.

Expected log on a peer that persists the change:

`GNP/1 M2.5 authenticated rename accepted: DESKTOP-TOFLGGG -> GENIABOOK (...); Device ID and trust anchors were preserved.`

## Next M2.5 work

Checkpoint 2 is implemented as **M2.5.2 Trusted Identity Lifecycle States** (`Active / Retired / Revoked`) with bounded local identity history. See `GNP1_MILESTONE2_5_2_TRUSTED_IDENTITY_LIFECYCLE.md`.


This checkpoint intentionally does not yet define the full lifecycle state machine. The next steps are:

- explicit `Active / Retired / Revoked` device states;
- identity-name history with authenticated timestamps;
- safe retirement/reactivation rules;
- irreversible or explicitly recoverable revocation semantics;
- UI and protocol policy for lifecycle transitions;
- migration from the current `Trusted / Changed / Revoked` registry placeholder state.
