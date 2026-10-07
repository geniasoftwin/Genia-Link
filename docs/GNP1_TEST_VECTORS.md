# GNP/1 Test Vectors — Public Draft 0.1

_Date: 2026-10-07_

These vectors are intended for independent compatibility checks of public GNP/1 primitive rules.

> The private scalar values below are deliberately trivial **test-only material**. They MUST NEVER be used as production keys.

All hexadecimal values are uppercase and contain no separators unless shown otherwise.

## Vector set A — fixed P-256 keys

Use NIST P-256.

### A1. Key 1

Private scalar:

```text
1
```

DER SubjectPublicKeyInfo:

```text
3059301306072A8648CE3D020106082A8648CE3D030107034200046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
```

Length: **91 bytes**.

### A2. Key 2

Private scalar:

```text
2
```

DER SubjectPublicKeyInfo:

```text
3059301306072A8648CE3D020106082A8648CE3D030107034200047CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC4766997807775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1
```

Length: **91 bytes**.

## Vector B — Signing Key ID

Input: Key 1 DER SubjectPublicKeyInfo from A1.

Rule:

```text
SigningKeyId = UPPERCASE_HEX(SHA256(SPKI))
```

Expected:

```text
5CD252FB0CE8932436FAF8CCD1040981B89EE4AD6B9FE9E2A2B7E71AACB27CD3
```

A conforming implementation MUST produce exactly this 64-character uppercase hexadecimal value.

## Vector C — ECDH raw secret + SHA-256 compatibility

Use:

- local private scalar = 1;
- peer public key = Key 2.

Raw P-256 ECDH shared secret:

```text
7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978
```

SHA-256 of that raw shared secret:

```text
23775201799B2234A18E8071E409CEC80D42632FE77534180AFDC533C9B76F81
```

This vector corresponds to the reference compatibility rule tested as **Android raw ECDH + SHA-256 matches .NET DeriveKeyFromHash**.

It is a primitive compatibility vector, not a complete trusted-session transcript.

## Vector D — Pairing SAS

Use:

Left DeviceId:

```text
00000000-0000-0000-0000-000000000001
```

Left public key: A1.

Right DeviceId:

```text
00000000-0000-0000-0000-000000000002
```

Right public key: A2.

Context:

```text
GENIALINK-PAIR-SAS-V2
```

Construct the input exactly as specified in [GNP/1 Specification](GNP1_SPEC.md):

```text
ASCII(context)
|| Left.DeviceId[16]
|| Left.PublicKeySPKI
|| Right.DeviceId[16]
|| Right.PublicKeySPKI
```

For these DeviceIds the .NET Guid byte representation is unambiguous with respect to the non-zero test octet because only the final byte differs.

Expected complete SHA-256:

```text
98E14569EC4FBBEE24FB15A7F88B76B9EF60BDBCC63F42BE3864066C03DFEEC9
```

First four bytes as a big-endian UInt32, modulo 1,000,000, produce:

```text
900201
```

Expected user-facing SAS:

```text
900 201
```

Both peers MUST produce the same value independent of which peer initiated pairing.

## Vector E — Pairing fingerprint

Rule:

```text
Fingerprint = UPPERCASE_HEX(SHA256(PublicKeySPKI)[0..15])
```

For Key 1, SHA-256 begins:

```text
5CD252FB0CE8932436FAF8CCD1040981...
```

Expected pairing fingerprint:

```text
5CD252FB0CE8932436FAF8CCD1040981
```

## Vector F — ECDSA verification

Signing public key: Key 1 SPKI from A1.

Message bytes are UTF-8:

```text
GNP/1 test vector: signing identity
```

Message hex:

```text
474E502F31207465737420766563746F723A207369676E696E67206964656E74697479
```

Valid ECDSA P-256 / SHA-256 signature encoded as RFC 3279 DER sequence:

```text
304502205B89769B720751E2B5301FD0B3F1E3625B1560607ADFBC408F071C1EFBDD09B4022100E52F6B094FE34DFD2F0616AD06C5EA48FE30903522FCFE185508AE3AB8DD2D95
```

Expected result:

```text
Verify = true
```

Changing any message byte or any signature byte MUST make verification fail.

The signature is one valid ECDSA signature; ECDSA signing is not required to reproduce the same DER bytes because nonce selection may differ between implementations.

## Vector G — negative behavioral vectors

These are normative expected outcomes even where Public Draft 0.1 does not yet publish the full raw byte transcript.

| Case | Expected result |
| --- | --- |
| GLP2 magic altered | reject pairing |
| Pairing protocol version != 3 | reject pairing |
| Pairing public key not P-256 SPKI | reject pairing |
| Pairing device name malformed UTF-8 | reject pairing |
| One side rejects SAS | pairing fails |
| Protected frame ciphertext modified | authentication failure |
| Protected frame replayed | authentication failure |
| Signed discovery payload modified | signature verification fails |
| Identity/capability revision lower than accepted revision | reject as replay/rollback |
| Same revision with conflicting authenticated state | reject conflict |
| Signing-key generation increased without continuity proof | reject |
| Relative transfer path escapes configured root | reject |
| Final file SHA-256 differs from FileOffer | transfer fails |
| Remembered IP now belongs to another host | trusted authentication fails; no file/service authorization |

## Vector provenance

Vectors B–F were generated directly from the primitive rules documented in the public M2.6.2 reference source:

- P-256 DER SubjectPublicKeyInfo;
- SHA-256 key identifier/fingerprint rules;
- raw P-256 ECDH followed by SHA-256 compatibility rule;
- pairing context and SAS construction;
- ECDSA P-256 + SHA-256 + RFC3279 DER verification.

The repository self-test already checks the corresponding runtime invariants. These fixed vectors add a stable cross-language target so a future Kotlin, native, TV, Mini or other GNP/1 implementation can test compatibility without copying the C# implementation.
