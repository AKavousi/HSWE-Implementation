# HSWE Implementation

A research prototype implementing the pairing-based Homomorphic Signature-based Witness Encryption (HSWE) construction from:

> *Homomorphic Signature-based Witness Encryption and Applications*


The initial implementation targets:

- BLS12-381 Type-III pairings
- A single signing authority
- Bounded non-negative integer messages
- Same-tag additive ciphertext aggregation
- Cross-tag aggregation
- Lookup-table-based bounded discrete-log recovery
- The stateful privacy-preserving HSWE wrapper
- Lattice-based HSWE construction
- Correctness testing and reproducible benchmarking

## Repository Structure

- `src/` — Rust library source code
- `docs/` — Protocol, design, and reproducibility documentation
- `tests/` — Integration tests
- `benches/` — Performance benchmarks
- `results/` — Generated benchmark data and figures


## Disclaimer

This is a research and educational prototype. It has not undergone an independent security audit and must not be used in production systems.
