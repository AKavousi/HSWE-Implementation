# HSWE Implementation

A research prototype implementing the pairing-based Homomorphic Signature-based Witness Encryption (HSWE) construction from:

> *Homomorphic Signature-based Witness Encryption and Applications*

## v0.1 Scope

The initial implementation targets:

- BLS12-381 Type-III pairings
- A single signing authority
- Canonical epoch tags
- BLS-style tag signatures as decryption witnesses
- Bounded non-negative integer messages
- Same-tag additive ciphertext aggregation
- Lookup-table-based bounded discrete-log recovery
- Correctness testing and reproducible benchmarking

## Out of Scope

v0.1 does not implement:

- Threshold BLS signatures
- Cross-tag aggregation
- The stateful privacy-preserving HSWE wrapper
- Lattice-based HSWE constructions
- Networking, blockchain integration, or smart contracts
- Production deployment features

## Documentation

- `docs/implementation-spec.md` — Machine-oriented protocol specification
- `docs/module-api-design.md` — Module and API design
- `docs/milestone-plan.md` — Step-by-step implementation plan

## Repository Structure

- `src/` — Rust library source code
- `docs/` — Protocol, design, and reproducibility documentation
- `tests/` — Integration tests
- `benches/` — Performance benchmarks
- `results/` — Generated benchmark data and figures

## Status

The project is currently completing the v0.1 design and environment-validation milestones.

## Disclaimer

This is a research and educational prototype. It has not undergone an independent security audit and must not be used in production systems.