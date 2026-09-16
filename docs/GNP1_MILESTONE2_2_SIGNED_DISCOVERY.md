# GNP/1 Milestone 2.2 — Signed Device Identity Advertisement

## Goal

Milestone 2.2 is the first network use of the persistent ECDSA P-256 signing identity introduced in M2.1.

A Genia Link device now broadcasts two discovery packets on the existing UDP discovery port:

1. `GLS1` — a new GNP/1 M2.2 signed identity advertisement;
2. `GLD2` — the existing RC4 discovery packet, byte-for-byte compatible with M1/M2.1.

The signed packet proves that the sender possesses the private ECDSA key corresponding to the public signing key carried by the packet and binds that key to the advertised Device ID, current device name/type, TCP ports, and existing ECDH fingerprint.

M2.2 does **not** by itself make an unknown peer trusted. Pairing and the existing trusted-session handshake remain the authority for trusted operations.

## Compatibility boundary

`ProtocolConstants.Version` remains `3`.

M2.2 intentionally does not modify:

- `DiscoveryPacket.cs` / legacy `GLD2` format;
- pairing protocol;
- ECDH trusted-session handshake;
- secure channel framing;
- transfer protocol;
- browse/download/preview messages;
- existing Device ID, ECDH key, ECDSA key, or trusted-device records.

An older RC4/M1/M2.1 peer sees `GLS1` as an unknown discovery datagram and silently ignores it, then immediately receives the unchanged `GLD2` packet. A new M2.2 peer verifies `GLS1` and suppresses the immediately following compatibility `GLD2` update for that Device ID so a verified signed peer is not downgraded merely by its own compatibility broadcast.

## GLS1 signed payload

All integers are big-endian. The ECDSA signature uses SHA-256 and RFC 3279 DER sequence encoding, matching the M2.1 cross-platform signing rules.

The signed bytes contain, in order:

- magic: `GLS1`;
- protocol version (`3`);
- identity version (`2` or later);
- Device ID (`Guid`, 16 bytes using the same .NET byte representation as existing discovery);
- transfer TCP port;
- pairing TCP port;
- device kind;
- signing-key generation;
- UTF-8 device-name length and bytes;
- existing 16-byte ECDH public-key fingerprint used by legacy discovery;
- signing-public-key length and SubjectPublicKeyInfo bytes.

The packet then appends:

- DER-signature length;
- ECDSA P-256 signature over every preceding byte through the signing public key.

`SigningKeyId` is not trusted as a transmitted string. The receiver derives it locally as SHA-256 of the verified SubjectPublicKeyInfo, exactly as in M2.1.

## What verification means

After `SignedDiscoveryPacket.ParseAndVerify` succeeds, Genia Link knows that:

- the packet was not modified after it was signed;
- the sender possessed the private key matching the included signing public key;
- the signature binds that key to the advertised Device ID, name, kind, ports, key generation, and ECDH fingerprint.

The resulting `DiscoveredDevice` is marked `DiscoveryIdentityProof.SignedIdentityV2` and carries the derived `SigningKeyId` plus identity/key-generation metadata.

This is a **self-signed identity proof**, not a trust decision. An unpaired attacker can still create a different signing key and self-assert arbitrary identity data. A later milestone must bind/pin the signing key through an authenticated pairing/trust operation before a signing key can authorize trusted actions.

## Replay and liveness boundary

M2.2 signs a discovery advertisement created when the local services start. It does not add a trusted timestamp, challenge, or per-announcement nonce. Therefore M2.2 detects modification but is not a cryptographic proof of current liveness and does not by itself prevent replay of a previously captured valid discovery advertisement.

This is intentional for the staged rollout. Freshness and trust binding belong in the authenticated GNP session/trust layer rather than being inferred from unauthenticated UDP broadcast traffic.

## Failure behavior

If the local signing key cannot create the M2.2 packet, Genia Link logs the failure and keeps the legacy `GLD2` discovery active. File transfer/pairing availability is therefore not lost because of the new optional discovery proof.

Malformed or unverifiable received discovery traffic is silently ignored to retain the RC4 anti-log-flood behavior.

Signed-peer discovery caches are bounded to 256 entries per service process. Identical already-verified `GLS1` packets are recognized by SHA-256 packet hash so repeated 2-second broadcasts do not require a fresh ECDSA verification each time; this reduces background CPU/battery cost without changing the replay boundary described above.

## Self-tests

M2.2 adds tests that verify:

- a `GLS1` packet round-trips and verifies with ECDSA P-256;
- Device ID/name/kind/ports/ECDH fingerprint survive the signed round-trip;
- `SigningKeyId` is derived from the verified public key;
- a legacy `GLD2` parser rejects/ignores `GLS1` rather than mis-parsing it;
- changing one signed byte causes verification failure.

`SecurityCheck.ps1` also hashes the verified M2.1 compatibility boundary and fails if M2.2 unexpectedly changes legacy discovery, protocol version, pairing, trusted-session handshake, or transfer protocol.

## Four-device acceptance test

Use the same M1/M2.1 installation identities; install/update over the current build rather than uninstalling.

Test devices:

- PC;
- Notebook;
- Android 1;
- Android 2.

### 1. Identity persistence

On every device confirm the existing lines still show the same values as M2.1:

- `Local Device ID: ...`
- `GNP/1 M2 Signing Key ID: ... (generation 1)`

No Device ID, signing key, or trusted pairing should change.

### 2. Local signed discovery active

Each M2.2 device should log:

`Local discovery active on UDP 47502 with GNP/1 M2.2 signed identity advertisements.`

### 3. Cross-device signature verification

With all four devices on the LAN, each active device should eventually log one verification line for each other M2.2 device it sees, for example:

`GNP/1 M2.2 signed discovery verified for <device>: <SigningKeyId> (generation 1).`

The remote `SigningKeyId` in that line must equal the local M2.1 signing-key ID shown by that remote device.

### 4. Compatibility

If practical, leave one device temporarily on M2.1 while another runs M2.2. They must still discover one another through the unchanged `GLD2` packet. The M2.1 device will not verify or display M2.2 signing proof; that is expected.

### 5. Regression

Repeat normal operations across Windows and Android:

- discovery;
- existing pairing/trusted-device recognition;
- small file transfer in both directions;
- remote folder/browse action if desired;
- Android Always Ready behavior separately from identity/discovery correctness.

M2.2 is accepted only if the existing transfer/trust behavior remains unchanged.

## Next boundary

The next trust milestone should authenticate/bind the M2 signing public key to an already authenticated pairing/trust event. Only after that binding should Genia Link treat a signing-key mismatch as a trusted-identity change rather than merely an observation from self-signed UDP discovery.
