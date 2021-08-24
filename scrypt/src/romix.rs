use core::convert::TryInto;

/// The Salsa20/8 core function
type Salsa20_8 = salsa20::Core<salsa20::R8>;

/// Execute the ROMix operation in-place.
/// b - the data to operate on; len must be a multiple of 128
/// v - a temporary variable to store the vector V; len must be (n >> log_f) * b.len()
/// t - a temporary variable; len must be b.len() * 2
/// n - the scrypt parameter N
/// log_f - a factor that reduces memory usage at the cost of computation; must always be less than or equal to log_n
/// To get a sense of how log_f works, the following formula calculates the total number
/// of operations performed for a given n and log_f:
/// ops(n, log_f) = 2 * n + 0.5 * n * (2**log_f - 1)
#[allow(clippy::many_single_char_names)]
pub(crate) fn scrypt_ro_mix(b: &mut [u8], v: &mut [u8], t: &mut [u8], n: usize, log_f: u32) {
    fn integerify(x: &[u8], n: usize) -> usize {
        // n is a power of 2, so n - 1 gives us a bitmask that we can use to perform a calculation
        // mod n using a simple bitwise and.
        let mask = n - 1;
        // This cast is safe since we're going to get the value mod n (which is a power of 2), so we
        // don't have to care about truncating any of the high bits off
        //let result = (LittleEndian::read_u32(&x[x.len() - 64..x.len() - 60]) as usize) & mask;
        let t = u32::from_le_bytes(x[x.len() - 64..x.len() - 60].try_into().unwrap());
        (t as usize) & mask
    }

    let len = b.len();
    let (t1, t2) = t.split_at_mut(len);

    for chunk in v.chunks_mut(len) {
        chunk.copy_from_slice(b);

        // Store 1 out of every 2**log_f values, so at 0 store every value, at 1 store every other value, etc.
        if log_f == 0 {
            scrypt_block_mix(chunk, b);
        } else {
            for _ in 0..((1 << log_f) >> 1) {
                scrypt_block_mix(b, t1);
                scrypt_block_mix(t1, b);
            }
        }
    }

    let f_mask = (1 << log_f) - 1;

    for _ in 0..n {
        let j = integerify(b, n);
        // Shift by log_f to get the nearest available stored block, rounded down.
        let chunk = &v[(j >> log_f) * len..((j >> log_f) + 1) * len];

        // When log_f > 0 we need to hash the fetched block to re-compute the hash of our
        // desired block.
        let n_hashes = j & f_mask;

        for i in 0..n_hashes {
            if i == 0 {
                scrypt_block_mix(chunk, t1);
            } else if i & 1 == 1 {
                scrypt_block_mix(t1, t2);
            } else {
                scrypt_block_mix(t2, t1);
            }
        }

        // Finally we xor and mix like usual, but need to use the right temporary variables.
        if n_hashes == 0 {
            xor(b, chunk, t1);
            scrypt_block_mix(t1, b);
        } else if n_hashes & 1 == 0 {
            xor(b, t2, t1);
            scrypt_block_mix(t1, b);
        } else {
            xor(b, t1, t2);
            scrypt_block_mix(t2, b);
        }
    }
}

/// Execute the BlockMix operation
/// input - the input vector. The length must be a multiple of 128.
/// output - the output vector. Must be the same length as input.
fn scrypt_block_mix(input: &[u8], output: &mut [u8]) {
    let mut x = [0u8; 64];
    x.copy_from_slice(&input[input.len() - 64..]);

    let mut t = [0u8; 64];

    for (i, chunk) in input.chunks(64).enumerate() {
        xor(&x, chunk, &mut t);

        let mut t2 = [0u32; 16];

        for (c, b) in t.chunks_exact(4).zip(t2.iter_mut()) {
            *b = u32::from_le_bytes(c.try_into().unwrap());
        }

        Salsa20_8::from(t2).generate(&mut x);

        let pos = if i % 2 == 0 {
            (i / 2) * 64
        } else {
            (i / 2) * 64 + input.len() / 2
        };

        output[pos..pos + 64].copy_from_slice(&x);
    }
}

fn xor(x: &[u8], y: &[u8], output: &mut [u8]) {
    for ((out, &x_i), &y_i) in output.iter_mut().zip(x.iter()).zip(y.iter()) {
        *out = x_i ^ y_i;
    }
}
