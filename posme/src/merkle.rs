use crate::hash;
use crate::{Block, LAMBDA};

/// A Merkle tree over arena blocks supporting O(log N) updates and proof generation.
///
/// Stored as a flat array: nodes[1] is the root, nodes[2..3] are level 1, etc.
/// Leaves start at index `n` (where n = number of blocks, must be power of 2).
#[derive(Clone)]
pub struct MerkleTree {
    nodes: Vec<[u8; LAMBDA]>,
    n: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from arena blocks.
    pub fn build(arena: &[Block]) -> Self {
        let n = arena.len();
        assert!(n.is_power_of_two());
        let mut nodes = vec![[0u8; LAMBDA]; 2 * n];

        // Leaves
        for i in 0..n {
            nodes[n + i] = hash::merkle_leaf(&arena[i]);
        }

        // Internal nodes (bottom-up)
        for i in (1..n).rev() {
            nodes[i] = hash::merkle_node(&nodes[2 * i], &nodes[2 * i + 1]);
        }

        Self { nodes, n }
    }

    /// Return the root hash.
    pub fn root(&self) -> [u8; LAMBDA] {
        self.nodes[1]
    }

    /// Update a single leaf and recompute the path to root. O(log N).
    pub fn update(&mut self, index: usize, block: &Block) {
        let mut pos = self.n + index;
        self.nodes[pos] = hash::merkle_leaf(block);
        pos /= 2;
        while pos >= 1 {
            self.nodes[pos] = hash::merkle_node(&self.nodes[2 * pos], &self.nodes[2 * pos + 1]);
            pos /= 2;
        }
    }

    /// Generate a Merkle proof (sibling hashes from leaf to root).
    pub fn proof(&self, index: usize) -> Vec<[u8; LAMBDA]> {
        let mut path = Vec::with_capacity(self.depth());
        let mut pos = self.n + index;
        while pos > 1 {
            let sibling = pos ^ 1;
            path.push(self.nodes[sibling]);
            pos /= 2;
        }
        path
    }

    /// Verify a Merkle proof against a given root.
    pub fn verify_proof(
        root: &[u8; LAMBDA],
        index: usize,
        leaf_hash: &[u8; LAMBDA],
        proof: &[[u8; LAMBDA]],
        n: usize,
    ) -> bool {
        let mut current = *leaf_hash;
        let mut pos = n + index;
        for sibling in proof {
            if pos % 2 == 0 {
                current = hash::merkle_node(&current, sibling);
            } else {
                current = hash::merkle_node(sibling, &current);
            }
            pos /= 2;
        }
        current == *root
    }

    fn depth(&self) -> usize {
        (self.n as f64).log2() as usize
    }
}

/// A Merkle tree over a sequence of roots (for root chain commitment).
pub struct RootChainTree {
    nodes: Vec<[u8; LAMBDA]>,
    n: usize, // padded to power of 2
    len: usize, // actual number of roots
}

impl RootChainTree {
    /// Build from a list of roots. Pads to next power of 2.
    pub fn build(roots: &[[u8; LAMBDA]]) -> Self {
        let len = roots.len();
        let n = len.next_power_of_two();
        let mut nodes = vec![[0u8; LAMBDA]; 2 * n];

        nodes[n..n + len].copy_from_slice(&roots[..len]);
        // Padding leaves are zero (deterministic)

        for i in (1..n).rev() {
            nodes[i] = hash::merkle_node(&nodes[2 * i], &nodes[2 * i + 1]);
        }

        Self { nodes, n, len }
    }

    pub fn root(&self) -> [u8; LAMBDA] {
        self.nodes[1]
    }

    pub fn proof(&self, index: usize) -> Vec<[u8; LAMBDA]> {
        assert!(index < self.len);
        let mut path = Vec::new();
        let mut pos = self.n + index;
        while pos > 1 {
            let sibling = pos ^ 1;
            path.push(self.nodes[sibling]);
            pos /= 2;
        }
        path
    }

    pub fn verify_proof(
        root: &[u8; LAMBDA],
        index: usize,
        value: &[u8; LAMBDA],
        proof: &[[u8; LAMBDA]],
        padded_n: usize,
    ) -> bool {
        let mut current = *value;
        let mut pos = padded_n + index;
        for sibling in proof {
            if pos % 2 == 0 {
                current = hash::merkle_node(&current, sibling);
            } else {
                current = hash::merkle_node(sibling, &current);
            }
            pos /= 2;
        }
        current == *root
    }
}
