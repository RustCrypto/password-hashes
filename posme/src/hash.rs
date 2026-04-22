use crate::{Block, LAMBDA};

/// Domain-separated BLAKE3 hash.
pub fn h(tag: &[u8], data: &[u8]) -> [u8; LAMBDA] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(tag);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Encode u32 as 4-byte big-endian (I2OSP).
pub fn i2osp(x: u32) -> [u8; 4] {
    x.to_be_bytes()
}

/// Derive a read address index from cursor and read index j.
pub fn addr_index(cursor: &[u8; LAMBDA], j: u32, n: usize) -> usize {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PoSME-addr-v1");
    hasher.update(cursor);
    hasher.update(&i2osp(j));
    let hash = hasher.finalize();
    let val = u32::from_be_bytes([hash.as_bytes()[0], hash.as_bytes()[1], hash.as_bytes()[2], hash.as_bytes()[3]]);
    val as usize % n
}

/// Derive the write address index from cursor.
pub fn write_index(cursor: &[u8; LAMBDA], d: u32, n: usize) -> usize {
    addr_index(cursor, d, n)
}

/// Chain the cursor with a read block: cursor = H(cursor || data || causal).
pub fn chain_cursor(cursor: &[u8; LAMBDA], block: &Block) -> [u8; LAMBDA] {
    let mut inp = [0u8; 3 * LAMBDA];
    inp[..LAMBDA].copy_from_slice(cursor);
    inp[LAMBDA..2 * LAMBDA].copy_from_slice(&block.data);
    inp[2 * LAMBDA..].copy_from_slice(&block.causal);
    h(b"", &inp)
}

/// Symbiotic data binding: new_data = H(old_data || cursor || old_causal).
pub fn symbiotic_data(old: &Block, cursor: &[u8; LAMBDA]) -> [u8; LAMBDA] {
    let mut inp = [0u8; 3 * LAMBDA];
    inp[..LAMBDA].copy_from_slice(&old.data);
    inp[LAMBDA..2 * LAMBDA].copy_from_slice(cursor);
    inp[2 * LAMBDA..].copy_from_slice(&old.causal);
    h(b"PoSME-write-v1", &inp)
}

/// Symbiotic causal binding: new_causal = H(old_causal || cursor || t).
pub fn symbiotic_causal(old: &Block, cursor: &[u8; LAMBDA], t: u32) -> [u8; LAMBDA] {
    let mut inp = [0u8; 2 * LAMBDA + 4];
    inp[..LAMBDA].copy_from_slice(&old.causal);
    inp[LAMBDA..2 * LAMBDA].copy_from_slice(cursor);
    inp[2 * LAMBDA..].copy_from_slice(&i2osp(t));
    h(b"PoSME-causal-v1", &inp)
}

/// Initialize block data. For i=0: H("init" || seed || 0). For i>0: H("init" || seed || i || prev || skip).
pub fn init_data(seed: &[u8], i: u32, prev: Option<&[u8; LAMBDA]>, skip: Option<&[u8; LAMBDA]>) -> [u8; LAMBDA] {
    let mut inp = Vec::with_capacity(seed.len() + 4 + 2 * LAMBDA);
    inp.extend_from_slice(seed);
    inp.extend_from_slice(&i2osp(i));
    if let Some(p) = prev {
        inp.extend_from_slice(p);
    }
    if let Some(s) = skip {
        inp.extend_from_slice(s);
    }
    h(b"PoSME-init-v1", &inp)
}

/// Initialize block causal hash: H("causal" || seed || i).
pub fn init_causal(seed: &[u8], i: u32) -> [u8; LAMBDA] {
    let mut inp = Vec::with_capacity(seed.len() + 4);
    inp.extend_from_slice(seed);
    inp.extend_from_slice(&i2osp(i));
    h(b"PoSME-causal-v1", &inp)
}

/// Initial transcript: T_0 = H("transcript" || seed || root_0).
pub fn transcript_init(seed: &[u8], root_0: &[u8; LAMBDA]) -> [u8; LAMBDA] {
    let mut inp = Vec::with_capacity(seed.len() + LAMBDA);
    inp.extend_from_slice(seed);
    inp.extend_from_slice(root_0);
    h(b"PoSME-transcript-v1", &inp)
}

/// Step transcript: T_t = H("transcript" || T_{t-1} || t || cursor || root_t).
pub fn transcript_step(
    t_prev: &[u8; LAMBDA],
    t: u32,
    cursor: &[u8; LAMBDA],
    root: &[u8; LAMBDA],
) -> [u8; LAMBDA] {
    let mut inp = [0u8; 3 * LAMBDA + 4];
    inp[..LAMBDA].copy_from_slice(t_prev);
    inp[LAMBDA..LAMBDA + 4].copy_from_slice(&i2osp(t));
    inp[LAMBDA + 4..2 * LAMBDA + 4].copy_from_slice(cursor);
    inp[2 * LAMBDA + 4..].copy_from_slice(root);
    h(b"PoSME-transcript-v1", &inp)
}

/// Fiat-Shamir challenge derivation.
pub fn fiat_shamir_challenges(
    final_transcript: &[u8; LAMBDA],
    root_chain_commitment: &[u8; LAMBDA],
    q: usize,
    k: u32,
) -> Vec<u32> {
    let mut sigma = [0u8; 2 * LAMBDA];
    sigma[..LAMBDA].copy_from_slice(final_transcript);
    sigma[LAMBDA..].copy_from_slice(root_chain_commitment);
    let sigma_hash = h(b"PoSME-fiat-shamir-v1", &sigma);

    let mut challenges = Vec::with_capacity(q);
    for i in 0..q {
        let mut inp = [0u8; LAMBDA + 4];
        inp[..LAMBDA].copy_from_slice(&sigma_hash);
        inp[LAMBDA..].copy_from_slice(&i2osp(i as u32));
        let ch = h(b"PoSME-challenge-v1", &inp);
        let val = u32::from_be_bytes([ch[0], ch[1], ch[2], ch[3]]);
        // Steps are 1-indexed: map to [1, k]
        let step = (val % k) + 1;
        challenges.push(step);
    }
    challenges
}

/// Leaf hash for Merkle tree.
pub fn merkle_leaf(block: &Block) -> [u8; LAMBDA] {
    h(b"\x00", &block.as_bytes())
}

/// Internal node hash for Merkle tree.
pub fn merkle_node(left: &[u8; LAMBDA], right: &[u8; LAMBDA]) -> [u8; LAMBDA] {
    let mut inp = [0u8; 2 * LAMBDA];
    inp[..LAMBDA].copy_from_slice(left);
    inp[LAMBDA..].copy_from_slice(right);
    h(b"\x01", &inp)
}
