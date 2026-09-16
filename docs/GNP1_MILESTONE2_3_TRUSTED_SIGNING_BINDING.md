# GNP/1 Milestone 2.3 — Trusted Signing Identity Binding

Status: development checkpoint on top of the verified M2.2 Signed Discovery snapshot.

## Goal

M2.2 proves that a `GLS1` sender possesses the ECDSA private key included in its own signed discovery packet. That proof is intentionally self-signed and therefore is not, by itself, a trust decision.

M2.3 binds the persistent ECDSA P-256 signing public key to the **already trusted Genia Link pairing relationship**. The migration does not trust UDP. It reuses the existing ECDH-derived trusted shared key, `TrustedSessionHandshake`, and `SecureChannel` before a signing key is written into `trusted-devices.json`.

After a successful M2.3 binding, a trusted device has two independent long-lived public identity components:

- the existing ECDH P-256 public key used by the current v3 trust/session mechanism;
- the ECDSA P-256 signing public key introduced in M2.1 and advertised in M2.2.

The existing Device ID remains unchanged.

## Compatibility boundary

M2.3 intentionally keeps:

- `ProtocolConstants.Version = 3`;
- TCP 47500 transfer protocol unchanged;
- TCP 47501 pairing protocol unchanged;
- UDP 47502 `GLD2` + `GLS1` discovery unchanged;
- `TrustedSessionHandshake.cs` unchanged;
- `TransferProtocol.cs` unchanged.

M2.3 adds one local-only endpoint:

- TCP 47503 — authenticated signing-identity binding.

An M2.2 or older peer simply has no listener on TCP 47503. Failure to bind never removes the existing pairing and never replaces a stored signing key from unauthenticated discovery.

## Binding flow

When a signed discovery packet is verified for a device that is already paired, and the trusted store has no signing-key binding (or sees a different key generation), the local node may attempt M2.3 binding against that peer's LAN address.

1. Client connects to TCP 47503.
2. Both sides run the existing `TrustedSessionHandshake` using the already paired ECDH relationship.
3. A `SecureChannel` is created from the trusted session key.
4. Client sends encrypted `GLI1` public identity data:
   - protocol version;
   - Device ID;
   - Identity version;
   - signing-key generation;
   - ECDSA P-256 SubjectPublicKeyInfo public key.
5. Server decrypts the frame and requires the `GLI1` Device ID to equal the Device ID authenticated by the trusted-session handshake.
6. Only then may the server persist the signing public key as belonging to that trusted device.
7. Server replies with its own encrypted `GLI1` identity and the client performs the same validation/persistence.

The `SigningKeyId` is never accepted as arbitrary text. Each side derives it locally as SHA-256 of the validated ECDSA P-256 SubjectPublicKeyInfo.

## Trusted store migration

Existing `trusted-devices.json` records remain readable. M2.3 adds optional fields:

- `SigningIdentityVersion`;
- `SigningKeyGeneration`;
- `SigningKeyId`;
- `SigningPublicKeyBase64`;
- `SigningKeyBoundAtUtc`.

Old records simply have no signing binding and are migrated in place after an authenticated M2.3 exchange. Existing pairing, Device ID and persistent authenticated endpoint metadata are preserved.

If the original paired ECDH public key changes through an explicit new pairing, any old signing-key binding is cleared with that identity change.

## Key-change rule

A self-signed UDP advertisement **cannot** replace a trusted signing key.

Authenticated M2.3 binding uses the following rule:

- no stored signing key → bind generation 1 or newer;
- same signing key → verify/preserve it; a lower generation is rejected;
- different signing key → accept only through authenticated M2.3 binding and only when `KeyGeneration` is strictly higher;
- different key at the same/lower generation → reject as conflict/rollback.

This provides a safe foundation for explicit signing-key rotation in a later milestone without making first-seen UDP data authoritative.

## Active identity mismatch behavior

Once a trusted peer has an authenticated signing-key binding, a fresh active discovery record must present the same verified signing key. A different signed key, or an unsigned active downgrade for that already-bound peer, is treated as an identity mismatch in the existing UI safety gate.

A sleeping/stale endpoint restored from authenticated history remains usable as a route hint because every real transfer still performs the existing trusted-session authentication. Authenticated incoming connections can also refresh the in-memory peer state from the stored signing binding.

## Security properties

- No private ECDH or ECDSA key is exported.
- No internet, HTTP, HTTPS, cloud, telemetry, certificate infrastructure, or third-party dependency is introduced.
- TCP 47503 is restricted by `LocalNetworkPolicy` to allowed local IPv4 addresses.
- `GLI1` is sent only inside the authenticated encrypted `SecureChannel`.
- Binding failure preserves existing trust rather than silently replacing identity.
- UDP `GLS1` remains a discovery proof, not the authority that writes/rotates trusted signing keys.

## Four-device acceptance test

Use the existing PC + Notebook + Android 1 + Android 2 M2.2 installations and update in place.

### 1. Build/security gate

Run:

```powershell
.\scripts\SecurityCheck-Android.ps1
```

Expected new line:

`GNP/1 M2.3 TRUSTED SIGNING IDENTITY BINDING CHECK PASSED`

### 2. Persistence regression

On all devices verify that these existing values remain unchanged:

- `Local Device ID`;
- `GNP/1 M2 Signing Key ID`;
- existing trusted pairings.

### 3. Listener

M2.3 nodes should log:

`GNP/1 M2.3 trusted signing-identity binding listener active on TCP 47503.`

### 4. Automatic trusted binding

With all four already-paired devices active on the same LAN, each trusted M2.3 relationship should eventually produce a line such as:

`GNP/1 M2.3 trusted signing identity bound for <device>: <SigningKeyId> (generation 1).`

The key ID must match the remote device's local `GNP/1 M2 Signing Key ID`.

The exchange may happen in either direction first. Repeated successful checks can log `verified` rather than `bound`.

### 5. Restart regression

Restart Genia Link and then reboot at least one Windows and one Android device. Pairings, Device IDs, local Signing Key IDs, and authenticated trusted signing-key bindings must remain stable.

### 6. Transfer regression

Repeat:

- Windows ↔ Windows;
- Windows ↔ Android;
- Android ↔ Android;
- browse/preview if convenient;
- Android Always Ready separately.

Normal file-transfer wire behavior must remain unchanged.

### 7. VPN note

If an Android VPN is configured to tunnel **all** applications and blocks LAN access, discovery, binding and transfer can all disappear because Genia Link is local-only. Use the VPN's LAN bypass/split tunneling or exclude Genia Link from the tunnel. This is a network-routing condition, not a Device Identity failure.

## Next boundary

After M2.3, the signing key is no longer merely self-asserted: it is pinned to the existing trusted relationship. The next major milestone can use that authenticated signing identity for signed trust records (`TrustGrant` / `TrustRevoke`) and then move toward authenticated GNP session establishment without depending forever on the legacy ECDH pairing database as the only trust authority.


## Fix2 — authenticated binding UI promotion

A successful authenticated M2.3 binding now immediately promotes the current peer record to `AuthenticatedTrustedIdentityV2` on both Windows and Android, provided the stored ECDH fingerprint still matches. This prevents a compatibility `GLD2` discovery packet from making an already-authenticated trusted peer appear to require re-pairing. A genuine ECDH fingerprint mismatch is never promoted or hidden.
## Compatibility discovery and key-change semantics

A legacy compatibility `GLD2` advertisement does not carry the M2 signing public key. Its arrival therefore means only **"no signing proof in this packet"** and must never by itself be shown as **"signing key changed"**.

For an already trusted peer, Genia Link reports a key conflict only when:

- the discovered ECDH fingerprint differs from the stored trusted ECDH identity; or
- a verified `SignedIdentityV2` / `AuthenticatedTrustedIdentityV2` proof contains a `SigningKeyId` different from the authenticated binding.

File transfer and remote browsing remain protected by the existing trusted ECDH session handshake, so accepting a compatibility `GLD2` packet as non-conflicting does not make that UDP packet a trust authority. A successful outgoing M2.3 binding is also promoted immediately into the active discovery/UI record, matching the already implemented incoming-binding behavior.

