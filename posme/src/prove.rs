use crate::hash;
use crate::merkle::{MerkleTree, RootChainTree};
use crate::{Block, Params, StepLog, LAMBDA};

#[derive(Clone, Debug)]
pub struct Proof {
    pub final_transcript: [u8; LAMBDA],
    pub root_chain_commitment: [u8; LAMBDA],
    pub root_chain_padded_n: usize,
    pub root_0_path: Vec<[u8; LAMBDA]>,
    pub step_proofs: Vec<StepProof>,
}

#[derive(Clone, Debug)]
pub struct StepProof {
    pub step_id: u32,
    pub cursor_in: [u8; LAMBDA],
    pub cursor_out: [u8; LAMBDA],
    pub root_before: [u8; LAMBDA],
    pub root_after: [u8; LAMBDA],
    pub root_chain_path_before: Vec<[u8; LAMBDA]>,
    pub root_chain_path_after: Vec<[u8; LAMBDA]>,
    pub reads: Vec<ReadWitness>,
    pub write: WriteWitness,
    pub writers: Vec<WriterProof>,
}

#[derive(Clone, Debug)]
pub struct ReadWitness {
    pub addr: usize,
    pub block: Block,
    pub merkle_path: Vec<[u8; LAMBDA]>,
}

#[derive(Clone, Debug)]
pub struct WriteWitness {
    pub addr: usize,
    pub old_block: Block,
    pub new_block: Block,
    pub merkle_path: Vec<[u8; LAMBDA]>,
}

#[derive(Clone, Debug)]
pub enum WriterType {
    Init,
    Step,
    Leaf,
}

#[derive(Clone, Debug)]
pub struct WriterProof {
    pub writer_type: WriterType,
    pub writer_step: Option<u32>,
    pub step_proof: Option<Box<StepProof>>,
    pub merkle_path: Option<Vec<[u8; LAMBDA]>>,
}

/// Find the last step that wrote to a given arena address before step `before_step`.
fn last_writer(addr: usize, before_step: u32, logs: &[StepLog]) -> Option<u32> {
    for log in logs.iter().rev() {
        if log.step >= before_step {
            continue;
        }
        if log.write_addr == addr {
            return Some(log.step);
        }
    }
    None
}

/// Build a Merkle tree for the arena state at a given step by replaying writes.
/// Returns the tree at the state just before `step_id` executed.
fn tree_at_step(
    params: &Params,
    seed: &[u8],
    logs: &[StepLog],
    step_id: u32,
) -> MerkleTree {
    let n = params.n;
    let mut arena = vec![crate::Block::zeroed(); n];
    crate::initialize(&mut arena, seed, n);

    for log in logs {
        if log.step >= step_id {
            break;
        }
        arena[log.write_addr] = log.new_block;
    }

    MerkleTree::build(&arena)
}

fn make_step_proof(
    params: &Params,
    seed: &[u8],
    step_id: u32,
    depth: usize,
    logs: &[StepLog],
    root_chain_tree: &RootChainTree,
) -> StepProof {
    let log = &logs[(step_id - 1) as usize];

    // Root chain proofs: step_id-1 and step_id map to root indices
    let root_idx_before = (step_id - 1) as usize;
    let root_idx_after = step_id as usize;
    let root_chain_path_before = root_chain_tree.proof(root_idx_before);
    let root_chain_path_after = root_chain_tree.proof(root_idx_after);

    // Build tree at the state before this step
    let tree_before = tree_at_step(params, seed, logs, step_id);

    // Read witnesses with Merkle proofs against root_before
    let mut reads = Vec::with_capacity(params.d);
    for j in 0..params.d {
        reads.push(ReadWitness {
            addr: log.read_addrs[j],
            block: log.read_blocks[j],
            merkle_path: tree_before.proof(log.read_addrs[j]),
        });
    }

    // Write witness with Merkle proof against root_before
    let write = WriteWitness {
        addr: log.write_addr,
        old_block: log.old_block,
        new_block: log.new_block,
        merkle_path: tree_before.proof(log.write_addr),
    };

    // Writer provenance proofs
    let mut writers = Vec::with_capacity(params.d);
    for j in 0..params.d {
        let addr = log.read_addrs[j];
        match last_writer(addr, step_id, logs) {
            None => {
                // Block was never written; it's still at init state.
                // Prove it exists in root_0 (index 0 in root chain).
                let init_tree = tree_at_step(params, seed, logs, 1);
                writers.push(WriterProof {
                    writer_type: WriterType::Init,
                    writer_step: None,
                    step_proof: None,
                    merkle_path: Some(init_tree.proof(addr)),
                });
            }
            Some(ws) if depth > 1 => {
                // Recurse: prove the writer step
                let sub_proof = make_step_proof(
                    params,
                    seed,
                    ws,
                    depth - 1,
                    logs,
                    root_chain_tree,
                );
                writers.push(WriterProof {
                    writer_type: WriterType::Step,
                    writer_step: Some(ws),
                    step_proof: Some(Box::new(sub_proof)),
                    merkle_path: None,
                });
            }
            Some(ws) => {
                let tree_after_write = tree_at_step(params, seed, logs, ws + 1);
                writers.push(WriterProof {
                    writer_type: WriterType::Leaf,
                    writer_step: Some(ws),
                    step_proof: None,
                    merkle_path: Some(tree_after_write.proof(addr)),
                });
            }
        }
    }

    StepProof {
        step_id,
        cursor_in: log.cursor_in,
        cursor_out: log.cursor_out,
        root_before: log.root_before,
        root_after: log.root_after,
        root_chain_path_before,
        root_chain_path_after,
        reads,
        write,
        writers,
    }
}

pub fn generate_proof(
    params: &Params,
    seed: &[u8],
    final_transcript: [u8; LAMBDA],
    roots: &[[u8; LAMBDA]],
    logs: &[StepLog],
) -> Proof {
    // Build root chain commitment
    let root_chain_tree = RootChainTree::build(roots);
    let root_chain_commitment = root_chain_tree.root();
    let root_chain_padded_n = roots.len().next_power_of_two();

    // root_0 proof in root chain
    let root_0_path = root_chain_tree.proof(0);

    // Derive Fiat-Shamir challenges
    let challenges = hash::fiat_shamir_challenges(
        &final_transcript,
        &root_chain_commitment,
        params.q,
        params.k,
    );

    // Generate step proofs for each challenged step
    let step_proofs: Vec<StepProof> = challenges
        .iter()
        .map(|&step_id| {
            make_step_proof(
                params,
                seed,
                step_id,
                params.r,
                logs,
                &root_chain_tree,
            )
        })
        .collect();

    Proof {
        final_transcript,
        root_chain_commitment,
        root_chain_padded_n,
        root_0_path,
        step_proofs,
    }
}
