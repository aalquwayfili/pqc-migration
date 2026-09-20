# Application contract — `filesigner`

**Status: reference implementation, awaiting human review.** Nothing in this directory
has been reviewed by a human cryptographer. AI checks are not human adjudication.

This contract is fixed **before** implementation and is binding on both the classical
version and the migrated version. Every clause below was verified empirically against the
pinned toolchain before being written down; §7 records how.

## 1. What the application does

A command-line file signer with persisted keys. Three entry points, identical in both
versions, so the same external tests drive either one:

```
filesigner keygen -priv <path> -pub <path>
filesigner sign   -priv <path> -in <file> -sig <path>
filesigner verify -pub  <path> -in <file> -sig <path>
```

## 2. Exit codes

Distinguishing an expected rejection from a failure is part of the contract, not a
testing convenience.

| Code | Meaning | Example |
|---|---|---|
| `0` | success; for `verify`, the signature is valid | |
| `1` | **expected rejection** — cryptographically invalid signature | wrong key, tampered file, wrong context |
| `2` | usage error | missing flag, unknown subcommand |
| `3` | malformed input | unparseable key, signature of wrong length |
| `4` | I/O error | file missing or unreadable |
| anything else | **not a rejection** — crash, panic, or timeout | must never be scored as a rejection |

A checker that cannot tell `1` from `3` or from a panic is not a checker. `1` and only
`1` means "the cryptography said no".

## 3. What is signed

**The original file bytes, exactly as they appear on disk.** No framing, no length
prefix, no canonicalisation, no envelope. `sign -in f` and `verify -in f` operate on
`f`'s bytes verbatim.

The two versions differ in how those bytes are consumed, and that difference is the
substance of the migration:

- **Classical (RSA):** SHA-256 digest of the file, then RSASSA-PKCS1-v1_5 over the digest.
- **Migrated (ML-DSA):** the file bytes are passed **directly** to ML-DSA. There is no
  application-level hash. ML-DSA-44 is used in its **pure** form (FIPS 204), not
  HashML-DSA.

## 4. Context string

The migrated version signs with a fixed ML-DSA context string:

```
filesigner/v1
```

- 13 bytes, US-ASCII, no trailing newline, no NUL terminator.
- Supplied on every sign and every verify. It is not optional and has no default of
  empty.
- ML-DSA permits 0–255 context bytes; this uses 13.
- On the OpenSSL side the identical bytes are supplied as
  `-pkeyopt context-string:filesigner/v1`.

A signature made under this context **must not** verify under a different context or
under the empty context. That is a required rejection, not an implementation detail
(§6.3).

The classical RSA version has no context concept. This is a genuine semantic gap the
migration introduces, and it is recorded here rather than papered over.

## 5. Key format on disk

Both versions persist keys in the standard DER structures, PEM-wrapped, so the
application's own key files are directly consumable by OpenSSL with no conversion step.

### Migrated version, ML-DSA-44

**Public key** — `SubjectPublicKeyInfo`, PEM label `PUBLIC KEY`, 1334 DER bytes:

```
30 82 05 32                                SEQUENCE (1330)
   30 0b                                   SEQUENCE (11)  AlgorithmIdentifier
      06 09 60 86 48 01 65 03 04 03 11     OID 2.16.840.1.101.3.4.3.17  (ML-DSA-44)
                                           parameters ABSENT
   03 82 05 21 00                          BIT STRING (1313) = 1 unused-bit byte + key
      <1312 raw public key bytes>
```

The 1312 raw bytes sit **directly** in the BIT STRING. They are not wrapped in an inner
OCTET STRING.

**Private key** — PKCS#8 `OneAsymmetricKey`, PEM label `PRIVATE KEY`, 2626 DER bytes,
using the **seed-and-expandedKey ("both")** form that OpenSSL 3.5 itself emits:

```
30 82 0a 3e                                SEQUENCE (2622)
   02 01 00                                INTEGER 0
   30 0b 06 09 <ML-DSA-44 OID>             AlgorithmIdentifier
   04 82 0a 2a                             OCTET STRING (2602)  privateKey
      30 82 0a 26                          SEQUENCE (2598)
         04 20 <32-byte seed>              OCTET STRING (32)
         04 82 0a 00 <2560-byte key>       OCTET STRING (2560)
```

The application **writes** the "both" form and **accepts** either the "both" form or a
bare 2560-byte expanded key, so it can consume keys from either side. When both are
present it derives from the seed and asserts the expanded key matches; a mismatch is
exit `3`.

### Classical version, RSA

RSA-2048. Public key `SubjectPublicKeyInfo` (PEM `PUBLIC KEY`), private key PKCS#8
(PEM `PRIVATE KEY`). Both are what `crypto/x509` marshals by default.

## 6. Required behaviour

### 6.1 Interoperability, both directions
1. A signature produced by the application verifies under OpenSSL 3.5.8.
2. A signature produced by OpenSSL 3.5.8 verifies through the application.

Both use the application's own key files, unmodified.

### 6.2 Key persistence
Keys survive write-to-disk and reload. A key generated, saved, reloaded and used to sign
produces a signature that verifies against the separately reloaded public key — and
against OpenSSL.

### 6.3 Required rejections (each must exit `1`, not crash)
| Case | Expectation |
|---|---|
| file modified after signing | reject |
| signature verified against a different key pair | reject |
| context string different from `filesigner/v1` | reject |
| empty context where `filesigner/v1` was used | reject |
| signature with a flipped bit | reject |
| truncated or over-long signature | reject as malformed, exit `3` |

### 6.4 Signatures are not byte-reproducible
ML-DSA signing is **randomized (hedged)** in both OpenSSL 3.5.8 and CIRCL as configured
here. Two signatures over the same message under the same key differ. Any test that
compares signature bytes is wrong; tests must verify.

## 7. How each clause was established

Every structural claim above was read off the pinned tools before implementation began,
not taken from documentation alone:

- OID, SPKI layout and PKCS#8 layout: `openssl asn1parse` on a key from
  `openssl genpkey -algorithm ML-DSA-44`, plus a hex dump of the DER.
- Sizes (32 / 1312 / 2560 / 2420): printed from CIRCL's own constants.
- Context behaviour and the rejection of a wrong context: signed with
  `-pkeyopt context-string:` and verified under a different one, both directions.
- Randomized signing: signed the same message twice and compared bytes.
- Cross-verification: CIRCL loaded the OpenSSL SPKI public key and verified an
  OpenSSL signature; OpenSSL verified a CIRCL signature.
- Seed/expanded agreement: derived a key from the PKCS#8 seed and compared it to the
  key parsed from the 2560-byte expanded blob.

Raw transcripts of these checks are in `evidence/`.

## 8. Pinned versions

| Component | Version |
|---|---|
| Go | 1.27.1 |
| CIRCL | v1.6.5 |
| OpenSSL (external checker) | 3.5.8 |

The distribution OpenSSL on this host is 3.0.18, which has **no** ML-DSA support; 3.5.8
is built from source into `toolchain/` and is the only OpenSSL the checker uses.
