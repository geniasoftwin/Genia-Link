# GNP/1 Milestone 2.5.2.1 — Revocation Session Enforcement

## Purpose

M2.5.2.1 closes the live-session and resume gap found during real-device testing of M2.5.2. A lifecycle `Revoked` decision must take effect against connections that authenticated before the decision, not only against the next connection attempt. A fresh SAS pairing after explicit Forget must also create a new resume authorization context rather than inheriting unfinished data from the former trust relationship.

The wire protocol remains version 3. This checkpoint changes local trust/session authorization and local resumable-transfer state only.

## Trust relationship identity

Trusted Identity Registry schema version 3 adds `TrustRelationshipId`, a local 128-bit hexadecimal identifier for the current explicit trust relationship with a Device ID.

The identifier is intentionally independent from:

- Device ID;
- paired ECDH fingerprint / `PairingKeyId`;
- ECDSA signing key ID and generation;
- device name;
- endpoint address.

Normal authenticated rename, signing-key rotation and `Retired -> Active` preserve `TrustRelationshipId`. Explicit pairing-trust replacement creates a new value. Explicit Forget removes the old value, and a later fresh SAS pairing creates another new value even when the remote Device ID and cryptographic device keys happen to be unchanged.

Schema-v1/v2 records that predate this field receive a deterministic migration value derived from the existing Device ID, pairing anchor and original trust timestamp, so migration remains stable across restarts. A newly created/re-paired trust record receives a fresh random value.

## Live-session lifetime

Every new trusted transfer session obtains a `TrustedSessionAuthorization` containing:

- remote Device ID;
- current `TrustRelationshipId`;
- a process-local lifetime cancellation token.

Windows and Android receiver loops link their per-connection cancellation token to this trust lifetime. Windows and Android outgoing user transfers do the same.

Policy:

- `Active -> Retired`: new trusted sessions are denied, but an already-authenticated transfer is not forcibly terminated;
- `Retired -> Active`: the same trust relationship remains valid;
- `Active/Retired -> Revoked`: the trust lifetime is immediately canceled;
- explicit Forget: the trust lifetime is immediately canceled and discarded;
- explicit pairing-trust replacement: the prior lifetime is canceled and a new trust relationship is created.

A receiver therefore stops an active transfer as soon as local trust becomes Revoked/forgotten instead of waiting for the next handshake.

## Resume authorization

Before M2.5.2.1, the Windows/Android deterministic resume key depended on file metadata. A partial file could therefore be rediscovered after a trust reset if the same file metadata was offered again.

M2.5.2.1 scopes the resume key to:

`Remote Device ID + TrustRelationshipId + file hash + size + relative path + file name`.

Consequences:

1. two different trusted devices cannot share a resume namespace for the same file;
2. a revoked/forgotten trust relationship cannot automatically resume under a fresh SAS pairing;
3. rename, signing-key rotation and Retired/reactivation still retain normal resume continuity because they do not replace the trust relationship.

Interrupted partial bytes may remain locally until the normal stale-part cleanup window. They are no longer authorized by a new trust relationship and therefore are not selected as the new transfer's resume source.

## Revoked acceptance behavior

The expected real-device sequence is now:

1. start a large transfer;
2. mark the peer `Revoked` locally;
3. the already-authenticated session is canceled immediately;
4. new connection attempts fail closed;
5. restart preserves `Revoked` and cannot resume the old session;
6. explicitly Forget the revoked identity;
7. complete a fresh SAS pairing;
8. the new trust relationship does not inherit the old resume offset.

The partial data from the old relationship can remain for bounded cleanup, but transfer authorization starts from the new relationship namespace.

## Security/self-test expectations

`GeniaLink.SelfTest` verifies that:

- active trust receives a stable relationship ID;
- authenticated rename preserves it;
- Retired denies new session authorization without canceling an already-issued lifetime;
- `Retired -> Active` preserves it;
- explicit pairing-anchor replacement creates a new relationship and cancels the previous lifetime;
- Revoked immediately cancels active session authorization;
- Revoked cannot issue new authorization;
- Forget + fresh SAS pairing creates a different relationship;
- trust-scoped resume keys are deterministic within one relationship but differ for another Device ID or relationship.

## Recommended acceptance test

Use a large file so there is time to change state while bytes are moving.

1. Start `ADMIN -> GENIAPIXIA` or the reverse direction and confirm progress is increasing.
2. On the receiving node, set the sending identity to `Revoked` while the transfer is active.
3. Confirm the transfer stops immediately and the log reports M2.5.2.1 trust/session invalidation.
4. Retry without changing lifecycle; confirm the new connection is rejected.
5. Restart the receiving application; confirm the identity remains Revoked and no old resume starts.
6. Explicitly Forget the revoked identity and perform a fresh SAS pairing.
7. Send the exact same file again. The receiver must start at offset 0 rather than the old partial offset.
8. Separately verify `Active -> Retired` during a transfer: the current transfer may finish, but a new transfer must be blocked until explicit `Retired -> Active`.
