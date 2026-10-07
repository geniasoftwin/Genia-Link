# Genia Link Threat Model

_Last updated: 2026-10-07_

This is a living engineering threat model for Genia Link. It documents intended trust boundaries, attacker assumptions and known limitations.

> This document is **not an independent security audit** and should not be read as a claim that the protocol or implementation is vulnerability-free.

## Security goals

Genia Link aims to protect:

- user file contents in transit;
- integrity of transferred files;
- persistent device identity and trust decisions;
- trusted capability state;
- resume state and destination-path confinement;
- administrative trust lifecycle state;
- print-job ownership and cancellation semantics in the M2.8 development line.

The project also tries to minimize unnecessary cloud/data exposure by keeping the application transfer path local-network-first.

## Main trust boundaries

### 1. Untrusted LAN → discovered peer

Any host on the local network can potentially transmit packets toward Genia Link endpoints.

Discovery therefore does not itself authorize file transfer, printing or identity replacement.

### 2. Pairing → trusted identity

The first trust decision is explicit. The user compares a SAS during pairing before the peer identity is persisted.

If a user accepts a mismatched SAS, the protocol cannot recover the intended human trust decision afterward.

### 3. Trusted identity → authenticated session

Subsequent sensitive operations require the peer to authenticate as the expected trusted identity. IP address, hostname, UI alias and remembered endpoint are not sufficient authorization.

### 4. Authenticated session → service capability

A trusted device still does not automatically receive every service. Service access is constrained by authenticated capability state such as `PrinterGateway`.

## Attacker model

The design considers an attacker who can:

- join the same LAN;
- send spoofed or malformed UDP discovery packets;
- open TCP connections to exposed local listeners;
- replay previously observed discovery assertions;
- attempt message truncation, corruption or reordering;
- obtain a previously used DHCP address;
- send malicious filenames, relative paths, lengths or unsupported message values;
- race a print cancellation against Windows spooler state;
- consume connection/CPU resources as a local denial-of-service attempt.

The model does **not** assume Genia Link can fully protect a device whose operating system, process, keystore/private keys or trusted peer has already been completely compromised.

## Main controls

### Cryptographic identity and pairing

- persistent ECDH P-256 identity for trusted-session key agreement;
- separate ECDSA P-256 signing identity for signed assertions;
- explicit SAS verification during initial pairing;
- trusted signing-key binding;
- continuity-verified signing-key rotation;
- Active / Retired / Revoked local identity lifecycle.

### Encrypted sessions

Trusted transport uses per-session derived keys and AES-256-GCM protected frames with sequence/replay protection.

Tampered or replayed protected frames are rejected.

### Discovery hardening

The development line has progressed from unsigned compatibility discovery to signed and replay-protected identity/capability assertions.

Signed discovery remains distinct from authorization: a self-signed unknown device does not become trusted merely because its signature is mathematically valid.

### Endpoint recovery

Remembered endpoints are written only after cryptographically authenticated activity and are treated as route hints. Reuse of an old IP still requires successful authentication as the expected DeviceId.

### File/path safety

Incoming names and relative paths are bounded and normalized. Traversal outside the configured root and unsafe reparse/symlink-style escapes are rejected by platform-specific policy.

Transfer completion requires expected length and SHA-256 verification.

### Bounded parsing and resource use

Protocol fields, batches, preview payloads and print payloads are deliberately bounded. Unknown/invalid values should be rejected rather than coerced into privileged behavior.

### Print cancellation

In M2.8.4.5, cancellation is bound to the accepted JobId and authenticated remote owner.

Before spooler submission, cancellation can stop local preparation. After submission, Windows cancellation requires exact job correlation and revalidation. If the exact job can no longer be proven, Genia Link reports cancellation as **not confirmed** and suppresses retry rather than risking duplicate printing.

## Known limitations / residual risk

- The protocol and implementation have not yet undergone an independent external cryptographic/security audit.
- Local network participants can observe IP addresses, connection timing and traffic volume even though protected payload contents are encrypted.
- A LAN attacker may still attempt denial of service through connection/resource pressure; complete per-IP abuse prevention is not claimed.
- A user who accepts the wrong SAS during first pairing can authorize the wrong peer.
- Compromise of an already trusted endpoint can allow that endpoint to exercise the capabilities it is authorized to provide/use until trust is retired/revoked/forgotten locally.
- The current long-term trusted key design should not be described as providing full forward secrecy against later compromise of long-term key material and previously recorded traffic.
- Platform and vendor drivers can limit observability. In particular, an old Windows printer driver may remove a job before physical print completion is knowable; Genia Link therefore uses conservative lifecycle semantics rather than inventing success.
- Availability depends on LAN/Wi-Fi behavior and operating-system background restrictions. Security guarantees do not imply guaranteed discovery/liveness.

## Out of scope / non-goals

Genia Link currently does not claim to:

- secure a fully compromised operating system;
- provide Internet-facing relay service security;
- replace enterprise network admission control;
- provide anonymity against LAN observers;
- guarantee physical printer success when the installed driver exposes no reliable state.

## Security reporting

Do not place exploit details, keys, credentials, real device identifiers or user data in a public issue.

See the repository [Security Policy](../SECURITY.md) for the preferred reporting path.

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Protocol notes](PROTOCOL.md)
- [Security implementation notes](SECURITY_IMPLEMENTATION.md)
- [Development status](DEVELOPMENT_STATUS.md)
