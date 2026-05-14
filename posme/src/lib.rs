//! # PoSME: Proof of Sequential Memory Execution
//!
//! A cryptographic primitive that enforces sustained sequential computation
//! via latency-bound pointer chasing over a mutable arena with causal hash
//! binding.
//!
//! ## Overview
//!
//! PoSME combines three properties no prior primitive provides simultaneously:
//! - **Sequential enforcement**: each step's read addresses depend on previous reads
//! - **Memory-hardness**: a mutable arena forces persistent storage
//! - **ASIC resistance**: bottleneck is DRAM random-access latency (~45ns), not computation
//!
//! ## Usage
//!
//! ```no_run
//! use posme::{Params, Prover};
//!
//! let params = Params {
//!     n: 1 << 16,  // 64K blocks (4 MiB arena)
//!     k: 1 << 16,  // rho = 1
//!     d: 8,
//!     q: 64,
//!     r: 2,
//! };
//! let seed = b"example-seed";
//!
//! let mut prover = Prover::new(&params, seed);
//! prover.execute();
//! let proof = prover.prove();
//! assert!(posme::verify(&params, seed, &proof));
//! ```

mod hash;
mod merkle;
mod prove;
mod verify;

pub use prove::{Proof, StepProof, ReadWitness, WriteWitness, WriterProof, WriterType};
pub use verify::verify;

/// Security parameter in bytes. All hashes produce 32-byte output.
pub const LAMBDA: usize = 32;

/// Block size: 32 bytes data + 32 bytes causal hash.
pub const BLOCK_SIZE: usize = 2 * LAMBDA;

/// PoSME parameters.
#[derive(Debug, Clone)]
pub struct Params {
    /// Number of arena blocks. Must be a power of 2.
    pub n: usize,
    /// Number of steps. Must be >= n. Recommended: 4*n (rho=4).
    pub k: u32,
    /// Reads per step. Must be >= 4. Recommended: 8.
    pub d: usize,
    /// Number of Fiat-Shamir challenges. Must be >= 64.
    pub q: usize,
    /// Recursion depth for provenance witnesses. Must be >= 2.
    pub r: usize,
}

impl Params {
    /// Write density rho = K/N.
    pub fn rho(&self) -> f64 {
        self.k as f64 / self.n as f64
    }

    /// Validate parameter constraints. Returns an error message if invalid.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.n.is_power_of_two() {
            return Err("n must be a power of 2");
        }
        if self.n < (1 << 20) {
            return Err("n must be >= 2^20 (arena must exceed L3 cache)");
        }
        if (self.k as usize) < self.n {
            return Err("k must be >= n (rho >= 1)");
        }
        if self.d < 4 {
            return Err("d must be >= 4");
        }
        if self.q < 64 {
            return Err("q must be >= 64");
        }
        if self.r < 2 {
            return Err("r must be >= 2");
        }
        Ok(())
    }

    /// Validate with relaxed constraints (for testing with small arenas).
    pub fn validate_relaxed(&self) -> Result<(), &'static str> {
        if !self.n.is_power_of_two() {
            return Err("n must be a power of 2");
        }
        if self.d < 1 {
            return Err("d must be >= 1");
        }
        if self.q < 1 {
            return Err("q must be >= 1");
        }
        if self.r < 1 {
            return Err("r must be >= 1");
        }
        Ok(())
    }
}

/// A single arena block: (data, causal).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Block {
    pub data: [u8; LAMBDA],
    pub causal: [u8; LAMBDA],
}

impl Block {
    pub fn zeroed() -> Self {
        Self {
            data: [0u8; LAMBDA],
            causal: [0u8; LAMBDA],
        }
    }

    pub fn as_bytes(&self) -> [u8; BLOCK_SIZE] {
        let mut out = [0u8; BLOCK_SIZE];
        out[..LAMBDA].copy_from_slice(&self.data);
        out[LAMBDA..].copy_from_slice(&self.causal);
        out
    }
}

/// Log entry for a single step, recording all data needed for proof generation.
#[derive(Clone)]
pub struct StepLog {
    pub step: u32,
    pub cursor_in: [u8; LAMBDA],
    pub cursor_out: [u8; LAMBDA],
    pub read_addrs: Vec<usize>,
    pub read_blocks: Vec<Block>,
    pub write_addr: usize,
    pub old_block: Block,
    pub new_block: Block,
    pub root_before: [u8; LAMBDA],
    pub root_after: [u8; LAMBDA],
}

/// The PoSME prover. Holds arena state and step logs.
pub struct Prover {
    params: Params,
    seed: Vec<u8>,
    pub arena: Vec<Block>,
    pub merkle: merkle::MerkleTree,
    pub transcript: [u8; LAMBDA],
    pub roots: Vec<[u8; LAMBDA]>,
    pub logs: Vec<StepLog>,
    executed: bool,
}

impl Prover {
    /// Create a new prover with initialized arena.
    pub fn new(params: &Params, seed: &[u8]) -> Self {
        let n = params.n;
        let mut arena = vec![Block::zeroed(); n];
        initialize(&mut arena, seed, n);
        let tree = merkle::MerkleTree::build(&arena);
        let root_0 = tree.root();

        let transcript = hash::transcript_init(seed, &root_0);

        let mut roots = Vec::with_capacity(params.k as usize + 1);
        roots.push(root_0);

        Self {
            params: params.clone(),
            seed: seed.to_vec(),
            arena,
            merkle: tree,
            transcript,
            roots,
            logs: Vec::with_capacity(params.k as usize),
            executed: false,
        }
    }

    /// Execute all K steps, recording logs for proof generation.
    pub fn execute(&mut self) {
        let n = self.params.n;
        let d = self.params.d;

        for t in 1..=self.params.k {
            let cursor_in = self.transcript;
            let root_before = self.merkle.root();

            // Pointer-chase reads
            let mut cursor = cursor_in;
            let mut read_addrs = Vec::with_capacity(d);
            let mut read_blocks = Vec::with_capacity(d);

            for j in 0..d {
                let a = hash::addr_index(&cursor, j as u32, n);
                read_addrs.push(a);
                let val = self.arena[a];
                read_blocks.push(val);
                cursor = hash::chain_cursor(&cursor, &val);
            }

            // Symbiotic write
            let w = hash::write_index(&cursor, d as u32, n);
            let old_block = self.arena[w];
            let new_data = hash::symbiotic_data(&old_block, &cursor);
            let new_causal = hash::symbiotic_causal(&old_block, &cursor, t);
            let new_block = Block {
                data: new_data,
                causal: new_causal,
            };
            self.arena[w] = new_block;

            // Update Merkle tree
            self.merkle.update(w, &new_block);
            let root_after = self.merkle.root();
            self.roots.push(root_after);

            // Update transcript
            self.transcript = hash::transcript_step(&self.transcript, t, &cursor, &root_after);

            self.logs.push(StepLog {
                step: t,
                cursor_in,
                cursor_out: cursor,
                read_addrs,
                read_blocks,
                write_addr: w,
                old_block,
                new_block,
                root_before,
                root_after,
            });
        }
        self.executed = true;
    }

    /// Generate a proof after execution.
    pub fn prove(&self) -> Proof {
        assert!(self.executed, "must call execute() before prove()");
        prove::generate_proof(
            &self.params,
            &self.seed,
            self.transcript,
            &self.roots,
            &self.logs,
        )
    }

    /// Return the final transcript value.
    pub fn final_transcript(&self) -> [u8; LAMBDA] {
        self.transcript
    }
}

/// Initialize the arena deterministically from seed.
fn initialize(arena: &mut [Block], seed: &[u8], n: usize) {
    // Block 0
    arena[0].data = hash::init_data(seed, 0, None, None);
    arena[0].causal = hash::init_causal(seed, 0);

    // Blocks 1..N-1
    for i in 1..n {
        let prev_data = arena[i - 1].data;
        let skip_data = arena[i / 2].data;
        arena[i].data = hash::init_data(seed, i as u32, Some(&prev_data), Some(&skip_data));
        arena[i].causal = hash::init_causal(seed, i as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_initialization() {
        let params = Params {
            n: 1 << 8,
            k: 1 << 8,
            d: 4,
            q: 4,
            r: 2,
        };
        let seed = b"test-seed";

        let p1 = Prover::new(&params, seed);
        let p2 = Prover::new(&params, seed);

        assert_eq!(p1.arena, p2.arena);
        assert_eq!(p1.transcript, p2.transcript);
        assert_eq!(p1.merkle.root(), p2.merkle.root());
    }

    #[test]
    fn deterministic_execution() {
        let params = Params {
            n: 1 << 8,
            k: 64,
            d: 4,
            q: 4,
            r: 2,
        };
        let seed = b"test-seed";

        let mut p1 = Prover::new(&params, seed);
        p1.execute();
        let mut p2 = Prover::new(&params, seed);
        p2.execute();

        assert_eq!(p1.transcript, p2.transcript);
        assert_eq!(p1.arena, p2.arena);
    }

    #[test]
    fn step_modifies_arena() {
        let params = Params {
            n: 1 << 8,
            k: 1,
            d: 4,
            q: 4,
            r: 1,
        };
        let seed = b"test-seed";

        let mut prover = Prover::new(&params, seed);
        let arena_before = prover.arena.clone();
        prover.execute();

        // At least one block should differ
        assert_ne!(prover.arena, arena_before);
    }

    #[test]
    fn transcript_changes_each_step() {
        let params = Params {
            n: 1 << 8,
            k: 10,
            d: 4,
            q: 4,
            r: 1,
        };
        let seed = b"test-seed";

        let mut prover = Prover::new(&params, seed);
        prover.execute();

        // All transcripts in roots should be unique
        let mut seen = std::collections::HashSet::new();
        for root in &prover.roots {
            assert!(seen.insert(*root), "duplicate root found");
        }
    }

    #[test]
    fn roundtrip_prove_verify() {
        let params = Params {
            n: 1 << 8,
            k: 1 << 8,
            d: 4,
            q: 4,
            r: 2,
        };
        let seed = b"roundtrip-test";

        let mut prover = Prover::new(&params, seed);
        prover.execute();
        let proof = prover.prove();

        assert!(verify(&params, seed, &proof));
    }

    #[test]
    fn tampered_transcript_fails() {
        let params = Params {
            n: 1 << 8,
            k: 1 << 8,
            d: 4,
            q: 4,
            r: 2,
        };
        let seed = b"tamper-test";

        let mut prover = Prover::new(&params, seed);
        prover.execute();
        let mut proof = prover.prove();
        proof.final_transcript[0] ^= 0xff;

        assert!(!verify(&params, seed, &proof));
    }

    #[test]
    fn wrong_seed_fails() {
        let params = Params {
            n: 1 << 8,
            k: 1 << 8,
            d: 4,
            q: 4,
            r: 2,
        };

        let mut prover = Prover::new(&params, b"correct-seed");
        prover.execute();
        let proof = prover.prove();

        assert!(!verify(&params, b"wrong-seed", &proof));
    }

    #[test]
    fn different_seeds_different_transcripts() {
        let params = Params {
            n: 1 << 8,
            k: 64,
            d: 4,
            q: 4,
            r: 1,
        };

        let mut p1 = Prover::new(&params, b"seed-a");
        p1.execute();
        let mut p2 = Prover::new(&params, b"seed-b");
        p2.execute();

        assert_ne!(p1.transcript, p2.transcript);
    }
}
