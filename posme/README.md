# RustCrypto: PoSME

[![crates.io](https://img.shields.io/crates/v/posme.svg)](https://crates.io/crates/posme)
[![docs.rs](https://docs.rs/posme/badge.svg)](https://docs.rs/posme)
![MSRV](https://img.shields.io/badge/rustc-1.70+-blue.svg)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE-APACHE)

Pure Rust implementation of [PoSME] (Proof of Sequential Memory Execution),
a cryptographic primitive that enforces sustained sequential computation via
latency-bound pointer chasing over a mutable arena with causal hash binding.

## About

PoSME is a memory-hard sequential proof primitive. Unlike password hashing
functions (Argon2, scrypt, Balloon), PoSME is designed for proving that a
party performed sustained sequential computation under concrete resource
constraints. It produces verifiable proofs, not password hashes.

**Key properties:**
- Sequential enforcement: each step's read addresses depend on previous reads
- Memory-hardness: a mutable arena forces persistent storage
- ASIC resistance: bottleneck is DRAM random-access latency (~45ns), not computation
- Verifiable: Fiat-Shamir proofs with recursive causal provenance
- No trusted setup required

**Relationship to password hashing:** PoSME shares memory-hardness goals with
Argon2/scrypt/Balloon but targets a different use case (sequential work proofs
rather than password storage). It uses BLAKE3 as its hash function.

## Usage

```rust
use posme::{Params, Prover};

let params = Params {
    n: 1 << 16,  // 64K blocks (4 MiB arena)
    k: 1 << 16,  // rho = 1
    d: 8,        // reads per step
    q: 64,       // Fiat-Shamir challenges
    r: 2,        // recursion depth
};
let seed = b"unique-task-id";

let mut prover = Prover::new(&params, seed);
prover.execute();
let proof = prover.prove();
assert!(posme::verify(&params, seed, &proof));
```

## Specification

- IETF Internet-Draft: [draft-condrey-cfrg-posme](https://datatracker.ietf.org/doc/draft-condrey-cfrg-posme/)
- Academic paper: "PoSME: Proof of Sequential Memory Execution via Latency-Bound Pointer Chasing with Causal Hash Binding"

## License

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).

[PoSME]: https://datatracker.ietf.org/doc/draft-condrey-cfrg-posme/
