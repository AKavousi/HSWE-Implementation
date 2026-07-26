# Backend Validation — HSWE v0.1

**Status:** Complete

**Milestone:** M1 — Cryptographic backend validation

**Date:** 2026-07-26

## Purpose

This document records the exact cryptographic backend selected for HSWE v0.1 and the capabilities verified before protocol code is implemented.

The implementation uses a Type-III pairing orientation:

\[
e: G_1 \times G_2 \rightarrow G_T.
\]

The planned HSWE mapping is:

| HSWE object | Group |
|---|---|
| Tag hash \(H_1(\tau)\) | \(G_1\) |
| Tag signature \(\sigma_\tau\) | \(G_1\) |
| Master public key \(P\) | \(G_2\) |
| Ciphertext component \(U\) | \(G_2\) |
| Ciphertext component \(V\) | \(G_T\) |
| Secret and ephemeral scalars | BLS12-381 scalar field \(\mathbb{F}_r\) |

## Pinned dependencies

| Crate | Version | Purpose |
|---|---:|---|
| `ark-bls12-381` | `0.5.0` | Concrete BLS12-381 pairing curve |
| `ark-ec` | `0.5.0` | Pairing, group, and hash-to-curve interfaces |
| `ark-ff` | `0.5.0` | Scalar-field operations |
| `ark-serialize` | `0.5.0` | Canonical serialization |
| `rand` | `0.8.5` | Randomness interface |
| `sha2` | `0.10.9` | SHA-256 support |
| `thiserror` | `2.0.18` | Structured errors |
| `zeroize` | `1.8.2` | Secret-memory hygiene support |

`Cargo.lock` is tracked to preserve the complete resolved dependency graph used for the research artifact.

## Verified capabilities

### Pairing

The backend successfully computes:

\[
e:G_1 \times G_2 \rightarrow G_T.
\]

The capability test confirmed non-degeneracy:

\[
e(g_1,g_2) \neq 1_{G_T}.
\]

It also confirmed bilinearity with fixed scalars \(a=5\) and \(b=7\):

\[
e(a g_1,b g_2)=e(g_1,g_2)^{ab}.
\]

### Target-group serialization

A pairing output in \(G_T\) successfully:

1. Serializes using Arkworks compressed canonical serialization.
2. Deserializes back to the identical group value.
3. Rejects a truncated byte encoding.

This supports the intended v0.1 use of canonical \(G_T\) bytes as:

- Ciphertext-component serialization.
- Discrete-log lookup-table keys.
- Stable test-fixture values.

## Pending M1 checks

## Hash-to-\(G_1\) decision

HSWE v0.1 uses Arkworks' built-in hash-to-curve composition:

```text
MapToCurveBasedHasher<
    G1Projective,
    DefaultFieldHasher<Sha256, 128>,
    WBMap<ark_bls12_381::g1::Config>
>
```

The fixed HSWE v0.1 domain-separation tag is:

```text
HSWE-V01_BLS12381G1_XMD:SHA-256_SSWU_RO_
```

The hasher processes the canonical tag bytes. It hashes those bytes to field elements with SHA-256, maps two field elements to the BLS12-381 \(G_1\) curve using the library-provided mapping configuration, adds the mapped points, and clears the cofactor. The resulting output is a point in the prime-order \(G_1\) subgroup.

The capability tests confirmed that:

- Identical tag bytes under the fixed domain-separation tag produce identical \(G_1\) points.
- Changing tag bytes changes the output in tests.
- Changing the domain-separation tag changes the output in tests.
- The resulting \(G_1\) point round-trips through canonical compressed serialization.

## Canonical compressed sizes

The following sizes were measured using the pinned dependency versions:

| Object | Group | Canonical compressed size |
|---|---|---:|
| Tag hash / tag signature | \(G_1\) | 48 bytes |
| Public key / ciphertext \(U\) | \(G_2\) | 96 bytes |
| Ciphertext \(V\) / lookup key | \(G_T\) | 576 bytes |

The 576-byte \(G_T\) encoding is the v0.1 lookup-table key format. HSWE does not assume that it matches any other library’s target-group encoding.

## Remaining M1 limitations

- This milestone validates API capability and behavior, not interoperability with another BLS implementation.
- The selected hash-to-curve composition is library-supported, but the exact Arkworks 0.5.0 implementation follows an earlier IETF hash-to-curve draft reference in its source. v0.1 fixes the crate version, domain-separation tag, and canonical encoding to avoid ambiguity.
- The test that changed tag/domain bytes establishes expected separation behavior for selected examples; it is not a proof that collisions cannot occur.

## Test command

```text
cargo test --test backend_capabilities
```