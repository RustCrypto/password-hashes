//! The variable length hash function used in the Argon2 algorithm.

use crate::{Error, Result};

use blake2::{
    digest::{self, Digest, VariableOutput},
    Blake2b512, Blake2bVar,
};

use core::convert::TryFrom;

pub fn variable_length_hash(inputs: &[&[u8]], out: &mut [u8]) -> Result<()> {
    if out.len() == 0 {
        return Err(Error::OutputTooShort);
    }

    let len_bytes = match u32::try_from(out.len()) {
        Ok(v) => v.to_le_bytes(),
        Err(_) => return Err(Error::OutputTooLong),
    };

    // Use blake2b directly if the output is small enough.
    if out.len() <= Blake2b512::output_size() {
        let mut digest = Blake2bVar::new(out.len()).unwrap();

        // Conflicting method name from `Digest` and `Update` traits
        digest::Update::update(&mut digest, &len_bytes);
        for input in inputs {
            digest::Update::update(&mut digest, input);
        }

        digest
            .finalize_variable(out)
            .expect("invalid Blake2bVar out length");
        return Ok(());
    }

    // Calculate longer hashes by first calculating a full 64 byte hash
    let half_hash_len = Blake2b512::output_size() / 2;
    let mut digest = Blake2b512::new();

    digest.update(len_bytes);
    for input in inputs {
        digest.update(input);
    }
    let mut last_output = digest.finalize_reset();

    // Then we write the first 32 bytes of this hash to the output
    out[..half_hash_len].copy_from_slice(&last_output[..half_hash_len]);

    // Next, we write a number of 32 byte blocks to the output.
    // Each block is the first 32 bytes of the hash of the last block.
    // The very last block of the output is excluded, and has a variable
    // length in range [1, 32].
    let whole_block_count = ((out.len() - 1) / half_hash_len) - 1;
    for chunk in out[half_hash_len..]
        .chunks_exact_mut(half_hash_len)
        .take(whole_block_count)
    {
        digest.update(&last_output);
        last_output = digest.finalize_reset();
        chunk.copy_from_slice(&last_output[..half_hash_len]);
    }

    // Calculate the last block with VarBlake2b.
    let whole_block_byte_count = half_hash_len * (whole_block_count + 1);
    let last_block_size = out.len() - whole_block_byte_count;
    let mut digest = Blake2bVar::new(last_block_size).unwrap();

    digest::Update::update(&mut digest, &last_output);
    digest
        .finalize_variable(&mut out[whole_block_byte_count..])
        .expect("invalid Blake2bVar out length");

    Ok(())
}
