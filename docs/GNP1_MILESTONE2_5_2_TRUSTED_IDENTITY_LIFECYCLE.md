# GNP/1 Milestone 2.5.2 — Trusted Identity Lifecycle States

## Purpose

M2.5.2 extends Trusted Identity State Management with an administrative lifecycle that is independent from cryptographic binding integrity.

The existing `TrustedIdentityRegistryState` continues to answer **whether the pinned cryptographic binding is intact** (`Trusted` / `Changed`). The new `TrustedIdentityLifecycleState` answers **whether the local user currently permits that identity to participate**:

- `Active` — trusted and allowed to participate normally;
- `Retired` — intentionally inactive, retained for history and possible explicit reactivation;
- `Revoked` — trust explicitly withdrawn; terminal until the record is explicitly forgotten and a new SAS pairing is completed.

This separation prevents an administrative decision such as retirement from being confused with a cryptographic key mismatch.

## Transition policy

Allowed transitions are deliberately narrow:

| From | To | Allowed | Meaning |
| --- | --- | --- | --- |
| Active | Retired | yes | Temporarily/institutionally remove a device from active use while retaining identity history. |
| Retired | Active | yes | Explicit local reactivation without a new SAS pairing, provided the cryptographic binding is still `Trusted`. |
| Active | Revoked | yes | Permanently withdraw the current local trust record. |
| Retired | Revoked | yes | Permanently withdraw a retired identity. |
| Revoked | Active/Retired | **no** | Revocation cannot be silently undone. Explicit Forget + new SAS pairing is required. |

The local event `Sequence` is the ordering authority. If the wall clock moves backwards, a lifecycle timestamp is clamped to the previous lifecycle timestamp rather than blocking an explicit security action such as Revoke. Reactivation is rejected when the cryptographic binding itself is `Changed`.

## Fail-closed enforcement

`TrustedDeviceStore.Get()` and normal `GetAll()` expose a device as usable trust only when the Trusted Identity Registry says both:

1. cryptographic state is `Trusted`;
2. lifecycle state is `Active`.

Consequently a `Retired` or `Revoked` identity:

- is not restored as a routable sleeping trusted endpoint;
- is suppressed from normal discovery UI rather than being presented as a fresh untrusted device;
- cannot refresh its verified endpoint;
- cannot propagate authenticated rename;
- cannot bind or rotate a signing identity;
- cannot pass the normal trusted-session lookup;
- cannot bypass lifecycle state by presenting a new pairing/ECDH anchor under the same Device ID.

For `Revoked`, even a valid historical Device ID, ECDH key and ECDSA signing identity are insufficient to restore trust. The local record must first be explicitly forgotten. As defense in depth, revocation also removes the corresponding compatibility entry from `trusted-devices.json`; the authoritative revoked/history record remains in `trusted-identities.json`.

## Retired behavior

`Retired` is intentionally reversible. The identity record, pairing anchor, signing identity and histories remain stored, but network use is disabled. When the local user explicitly returns it to `Active`, no SAS pairing is required as long as the cryptographic binding remains intact.

Routable endpoint data is cleared when an identity becomes inactive. After reactivation the endpoint must be learned again through normal authenticated discovery/traffic rather than reusing stale routing data.

## Revoked behavior

`Revoked` is terminal inside the retained record. Neither startup synchronization, signed discovery, authenticated rename, signing-key rotation nor pairing-anchor replacement can convert the record back to active trust.

The recovery path is explicit:

1. choose **Forget** for the revoked identity;
2. remove the retained local trust record;
3. perform a fresh SAS pairing if the device should be trusted again.

Registry-only records are intentionally preserved when the compatibility `trusted-devices.json` database is missing or recovered. Windows settings also exposes such records, and Forget can remove them, so fail-closed revocation cannot become an unmanageable permanent lockout after storage recovery.

## Rollout and downgrade rule

The wire protocol remains compatible with M2.5.1 peers, so remote peers do not all need to upgrade simultaneously. However, once a local installation has written schema-v3 lifecycle/session state, **do not downgrade that same installation to an older build as a supported operating mode**. Older builds do not understand `Active / Retired / Revoked`.

Revoked is hardened against this class by deleting its compatibility trusted-device entry, so the old transfer path no longer has the former ECDH trust record to reuse. Retired intentionally retains its compatibility identity to support reactivation, therefore a local downgrade could ignore the Retired policy. Upgrade/rollback testing should use a backup/copy of app data rather than running an older production binary over lifecycle-managed state.

## Identity history

Schema version 3 retains a bounded local identity-event journal and adds `TrustRelationshipId` for trust-scoped session/resume enforcement. Each event has a monotonically increasing local `Sequence`, timestamp and event type. Current event types are:

- `Trusted`;
- `AuthenticatedRename`;
- `SigningKeyRotated`;
- `LifecycleChanged`;
- `PairingTrustReplaced`.

The journal is bounded to 128 retained entries per identity. Signing-key history remains separately bounded to 32 retired keys. The journal is intended for lifecycle/audit context; it does not replace the cryptographic trust anchors.

M2.5.2/M2.5.2.1 migrate older registry records into schema v3. Older `RegistryState.Revoked = 3` records, if present, are normalized into cryptographic `Trusted` plus lifecycle `Revoked`, preserving the fail-closed meaning while separating the two state dimensions.

## Windows management UI

Windows **Settings → Trusted devices** now shows lifecycle state and exposes:

- **Перевести в Retired / Вернуть в Active**;
- **Revoke**;
- existing **Forget**.

Retire and Revoke require explicit user action; Revoke displays a terminal-state warning. Lifecycle changes apply immediately and are not deferred until the settings dialog is saved.

Android participates in persistence and enforcement in this checkpoint, including background availability behavior, but does not yet expose lifecycle-management controls in its UI.

## Local scope in M2.5.2

Lifecycle is currently a **local trust policy**. Revoking device B on device A does not automatically instruct devices C and D to revoke B. No central authority or network-wide governance is introduced by this checkpoint.

Authenticated distribution of administrative lifecycle decisions would require a separately designed authorization/signature model and is intentionally outside M2.5.2.

## Relationship to authenticated rename freshness

M2.5.2 records authenticated rename events in local history, but it does **not** change the `GLS1` wire format. The checkpoint-1 freshness limitation therefore remains: a previously captured, historically valid `GLS1` packet is signed but not totally ordered by a monotonic authenticated name revision.

Lifecycle state itself is not derived from rename chronology, so a replayed old name cannot reactivate a Retired/Revoked identity. A future M2.5 hardening step should add replay-resistant name ordering before rename history is treated as authoritative chronological evidence across nodes.

## Security/self-test expectations

`GeniaLink.SelfTest` verifies that:

- a newly trusted identity starts `Active`;
- `Active -> Retired` disables active trust;
- authenticated rename is rejected while Retired;
- startup synchronization cannot reactivate or rename Retired;
- explicit `Retired -> Active` works without replacing trust anchors;
- lifecycle transitions are written to identity history;
- `Active -> Revoked` disables active trust;
- `Revoked -> Active` is rejected;
- pairing-anchor replacement while Revoked is rejected;
- revocation remains present in identity history.

## Recommended acceptance test

1. Start with two already paired M2.5.2 devices and verify normal bidirectional transfer.
2. On Windows, open Settings → Trusted devices and set the peer to `Retired`.
3. Confirm it disappears from normal active discovery/SendTo use and trusted transfer is rejected.
4. Restart Genia Link and confirm the peer remains `Retired` and is not restored as a sleeping active endpoint.
5. Return it explicitly to `Active`; wait for fresh discovery and confirm transfer works again without SAS pairing.
6. Set the peer to `Revoked`.
7. Restart both applications and confirm signed discovery/traffic does not restore trust.
8. Confirm `Active` reactivation is unavailable for the revoked record.
9. Choose Forget, then perform a fresh SAS pairing; only this explicit path should create usable trust again.


## M2.5.2.1 extension

Real-device acceptance testing showed that M2.5.2 correctly blocked new connections after Revoked but an already-authenticated transfer could continue, and old resume state could survive Forget + new pairing. M2.5.2.1 closes that gap with trust-relationship lifetime cancellation and trust-scoped resume keys. See `GNP1_MILESTONE2_5_2_1_REVOCATION_SESSION_ENFORCEMENT.md`.
