//! The variable length hash function used in the Argon2 algorithm.

use crate::{Error, Result};

use blake2::{
    Blake2b512, Blake2bVarCore,
    digest::{
        Digest,
        block_api::{UpdateCore, VariableOutputCore},
        block_buffer::LazyBuffer,
    },
};

pub fn blake2b_long(inputs: &[&[u8]], out: &mut [u8]) -> Result<()> {
    if out.is_empty() {
        return Err(Error::OutputTooShort);
    }

    let len_bytes = u32::try_from(out.len())
        .map(|v| v.to_le_bytes())
        .map_err(|_| Error::OutputTooLong)?;

    // Use blake2b directly if the output is small enough.
    if let Ok(mut hasher) = Blake2bVarCore::new(out.len()) {
        let mut buf = LazyBuffer::new(&len_bytes);

        for input in inputs {
            buf.digest_blocks(input, |blocks| hasher.update_blocks(blocks));
        }

        let mut full_out = Default::default();
        hasher.finalize_variable_core(&mut buf, &mut full_out);
        let out_src = &full_out[..out.len()];
        out.copy_from_slice(out_src);

        return Ok(());
    }

    // Calculate longer hashes by first calculating a full 64 byte hash
    let half_hash_len = Blake2b512::output_size() / 2;
    let mut digest = Blake2b512::new();

    digest.update(len_bytes);
    for input in inputs {
        digest.update(input);
    }
    let mut last_output = digest.finalize();

    // Then we write the first 32 bytes of this hash to the output
    out[..half_hash_len].copy_from_slice(&last_output[..half_hash_len]);

    // Next, we write a number of 32 byte blocks to the output.
    // Each block is the first 32 bytes of the hash of the last block.
    // The very last block of the output is excluded, and has a variable
    // length in range [1, 32].
    let mut counter = 0;
    let out_len = out.len();
    for chunk in out[half_hash_len..]
        .chunks_exact_mut(half_hash_len)
        .take_while(|_| {
            counter += half_hash_len;
            out_len - counter > 64
        })
    {
        last_output = Blake2b512::digest(last_output);
        chunk.copy_from_slice(&last_output[..half_hash_len]);
    }

    // Calculate the last block with VarBlake2b.
    let out = &mut out[counter..];

    let mut hasher = Blake2bVarCore::new(out.len())
        .expect("The output is guaranteed to be smaller than 64 bytes");
    let mut buf = LazyBuffer::new(&last_output);
    let mut full_out = Default::default();
    hasher.finalize_variable_core(&mut buf, &mut full_out);
    let out_src = &full_out[..out.len()];
    out.copy_from_slice(out_src);

    Ok(())
}
