use byte_tools::copy as copy_memory;


/// The salsa20/8 core function.
#[inline(never)]
fn salsa20_8(input: &[u8], output: &mut [u8]) {

    macro_rules! read_into {
        ($idx:expr) => {
            u32::from_le_bytes([input[4*$idx], input[4*$idx+1], input[4*$idx+2], input[4*$idx+3]])
        };
    }
    let mut x: [u32; 16] = [
        read_into!(0),
        read_into!(1),
        read_into!(2),
        read_into!(3),
        read_into!(4),
        read_into!(5),
        read_into!(6),
        read_into!(7),
        read_into!(8),
        read_into!(9),
        read_into!(10),
        read_into!(11),
        read_into!(12),
        read_into!(13),
        read_into!(14),
        read_into!(15),
    ];

    macro_rules! run_round (
        ($($set_idx:expr, $idx_a:expr, $idx_b:expr, $rot:expr);*) => { {
            $( x[$set_idx] ^= x[$idx_a].wrapping_add(x[$idx_b]).rotate_left($rot); )*
        } }
    );

    macro_rules! repeat4 (
        ($block:expr) => {
            $block;
            $block;
            $block;
            $block;
        }
    );

    repeat4!({
        run_round!(
            0x4, 0x0, 0xc, 7;
            0x8, 0x4, 0x0, 9;
            0xc, 0x8, 0x4, 13;
            0x0, 0xc, 0x8, 18;
            0x9, 0x5, 0x1, 7;
            0xd, 0x9, 0x5, 9;
            0x1, 0xd, 0x9, 13;
            0x5, 0x1, 0xd, 18;
            0xe, 0xa, 0x6, 7;
            0x2, 0xe, 0xa, 9;
            0x6, 0x2, 0xe, 13;
            0xa, 0x6, 0x2, 18;
            0x3, 0xf, 0xb, 7;
            0x7, 0x3, 0xf, 9;
            0xb, 0x7, 0x3, 13;
            0xf, 0xb, 0x7, 18;
            0x1, 0x0, 0x3, 7;
            0x2, 0x1, 0x0, 9;
            0x3, 0x2, 0x1, 13;
            0x0, 0x3, 0x2, 18;
            0x6, 0x5, 0x4, 7;
            0x7, 0x6, 0x5, 9;
            0x4, 0x7, 0x6, 13;
            0x5, 0x4, 0x7, 18;
            0xb, 0xa, 0x9, 7;
            0x8, 0xb, 0xa, 9;
            0x9, 0x8, 0xb, 13;
            0xa, 0x9, 0x8, 18;
            0xc, 0xf, 0xe, 7;
            0xd, 0xc, 0xf, 9;
            0xe, 0xd, 0xc, 13;
            0xf, 0xe, 0xd, 18
        )
    });

    for i in 0..16 {
        (&mut output[i * 4..(i + 1) * 4]).copy_from_slice(&x[i].wrapping_add(u32::from_le_bytes([input[i * 4], input[i * 4 + 1], input[i * 4 + 2], input[i * 4 + 3]])).to_le_bytes());
    }
}

fn xor(x: &[u8], y: &[u8], output: &mut [u8]) {
    for ((out, &x_i), &y_i) in output.iter_mut().zip(x.iter()).zip(y.iter()) {
        *out = x_i ^ y_i;
    }
}

/// Execute the BlockMix operation
/// input - the input vector. The length must be a multiple of 128.
/// output - the output vector. Must be the same length as input.
fn scrypt_block_mix(input: &[u8], output: &mut [u8]) {
    let mut x = [0u8; 64];
    copy_memory(&input[input.len() - 64..], &mut x);

    let mut t = [0u8; 64];

    for (i, chunk) in input.chunks(64).enumerate() {
        xor(&x, chunk, &mut t);
        salsa20_8(&t, &mut x);
        let pos = if i % 2 == 0 { (i / 2) * 64 } else { (i / 2) * 64 + input.len() / 2 };
        copy_memory(&x, &mut output[pos..pos + 64]);
    }
}

/// Execute the ROMix operation in-place.
/// b - the data to operate on
/// v - a temporary variable to store the vector V
/// t - a temporary variable to store the result of the xor
/// n - the scrypt parameter N
pub(crate) fn scrypt_ro_mix(b: &mut [u8], v: &mut [u8], t: &mut [u8], n: usize) {
    fn integerify(x: &[u8], n: usize) -> usize {
        // n is a power of 2, so n - 1 gives us a bitmask that we can use to perform a calculation
        // mod n using a simple bitwise and.
        let mask = n - 1;
        // This cast is safe since we're going to get the value mod n (which is a power of 2), so we
        // don't have to care about truncating any of the high bits off
        (u32::from_le_bytes([x[x.len() - 64], x[x.len() - 63], x[x.len() - 62], x[x.len() - 61]]) as usize) & mask
    }

    let len = b.len();

    for chunk in v.chunks_mut(len) {
        copy_memory(b, chunk);
        scrypt_block_mix(chunk, b);
    }

    for _ in 0..n {
        let j = integerify(b, n);
        xor(b, &v[j * len..(j + 1) * len], t);
        scrypt_block_mix(t, b);
    }
}
