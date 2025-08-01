#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
/// Permute Salsa20 block to column major order
const PIVOT_ABCD: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
/// Inverse of PIVOT_ABCD
const INVERSE_PIVOT_ABCD: [usize; 16] = const {
    let mut index = [0; 16];
    let mut i = 0;
    while i < 16 {
        let mut inverse = 0;
        while inverse < 16 {
            if PIVOT_ABCD[inverse] == i {
                index[i] = inverse;
                break;
            }
            inverse += 1;
        }
        i += 1;
    }
    index
};

/// Execute the ROMix operation in-place.
/// b - the data to operate on
/// v - a temporary variable to store the vector V
/// t - a temporary variable to store the result of the xor
/// n - the scrypt parameter N
#[allow(clippy::many_single_char_names)]
pub(crate) fn scrypt_ro_mix(b: &mut [u8], v: &mut [u8], t: &mut [u8], n: usize) {
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

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    for chunk in b.chunks_exact_mut(64) {
        let mut t = [0u32; 16];
        for (c, b) in chunk.chunks_exact(4).zip(t.iter_mut()) {
            *b = u32::from_ne_bytes(c.try_into().unwrap());
        }
        chunk.chunks_exact_mut(4).enumerate().for_each(|(i, b)| {
            b.copy_from_slice(&t[PIVOT_ABCD[i]].to_ne_bytes());
        });
    }

    for chunk in v.chunks_mut(len) {
        chunk.copy_from_slice(b);
        scrypt_block_mix(chunk, b);
    }

    for _ in 0..n {
        let j = integerify(b, n);
        xor(b, &v[j * len..(j + 1) * len], t);
        scrypt_block_mix(t, b);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    for chunk in b.chunks_exact_mut(64) {
        let mut t = [0u32; 16];
        for (c, b) in chunk.chunks_exact(4).zip(t.iter_mut()) {
            *b = u32::from_ne_bytes(c.try_into().unwrap());
        }
        chunk.chunks_exact_mut(4).enumerate().for_each(|(i, b)| {
            b.copy_from_slice(&t[INVERSE_PIVOT_ABCD[i]].to_ne_bytes());
        });
    }
}

/// Execute the BlockMix operation
/// input - the input vector. The length must be a multiple of 128.
/// output - the output vector. Must be the same length as input.
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn scrypt_block_mix(input: &[u8], output: &mut [u8]) {
    use salsa20::{
        SalsaCore,
        cipher::{StreamCipherCore, typenum::U4},
    };

    type Salsa20_8 = SalsaCore<U4>;

    let mut x = [0u8; 64];
    x.copy_from_slice(&input[input.len() - 64..]);

    let mut t = [0u8; 64];

    for (i, chunk) in input.chunks(64).enumerate() {
        xor(&x, chunk, &mut t);

        let mut t2 = [0u32; 16];

        for (c, b) in t.chunks_exact(4).zip(t2.iter_mut()) {
            *b = u32::from_le_bytes(c.try_into().unwrap());
        }

        Salsa20_8::from_raw_state(t2).write_keystream_block((&mut x).into());

        let pos = if i % 2 == 0 {
            (i / 2) * 64
        } else {
            (i / 2) * 64 + input.len() / 2
        };

        output[pos..pos + 64].copy_from_slice(&x);
    }
}

/// Execute the BlockMix operation
/// input - the input vector. The length must be a multiple of 128.
/// output - the output vector. Must be the same length as input.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn scrypt_block_mix(input: &[u8], output: &mut [u8]) {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;

    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    macro_rules! mm_rol_epi32x {
        ($w:expr, $amt:literal) => {{
            let w = $w;
            _mm_or_si128(_mm_slli_epi32(w, $amt), _mm_srli_epi32(w, 32 - $amt))
        }};
    }

    let mut x = [0u8; 64];
    x.copy_from_slice(&input[input.len() - 64..]);

    let mut a = unsafe { _mm_loadu_si128(x.as_ptr().cast()) };
    let mut b = unsafe { _mm_loadu_si128(x.as_ptr().add(16).cast()) };
    let mut c = unsafe { _mm_loadu_si128(x.as_ptr().add(32).cast()) };
    let mut d = unsafe { _mm_loadu_si128(x.as_ptr().add(48).cast()) };

    for (i, chunk) in input.chunks(64).enumerate() {
        let pos = if i % 2 == 0 {
            (i / 2) * 64
        } else {
            (i / 2) * 64 + input.len() / 2
        };

        unsafe {
            a = _mm_xor_si128(a, _mm_loadu_si128(chunk.as_ptr().cast()));
            b = _mm_xor_si128(b, _mm_loadu_si128(chunk.as_ptr().add(16).cast()));
            c = _mm_xor_si128(c, _mm_loadu_si128(chunk.as_ptr().add(32).cast()));
            d = _mm_xor_si128(d, _mm_loadu_si128(chunk.as_ptr().add(48).cast()));

            let saves = [a, b, c, d];

            for _ in 0..8 {
                b = _mm_xor_si128(b, mm_rol_epi32x!(_mm_add_epi32(a, d), 7));
                c = _mm_xor_si128(c, mm_rol_epi32x!(_mm_add_epi32(b, a), 9));
                d = _mm_xor_si128(d, mm_rol_epi32x!(_mm_add_epi32(c, b), 13));
                a = _mm_xor_si128(a, mm_rol_epi32x!(_mm_add_epi32(d, c), 18));

                // a stays in place
                // b = left shuffle d by 1 element
                d = _mm_shuffle_epi32(d, 0b00_11_10_01);
                // c = left shuffle c by 2 elements
                c = _mm_shuffle_epi32(c, 0b01_00_11_10);
                // d = left shuffle b by 3 elements
                b = _mm_shuffle_epi32(b, 0b10_01_00_11);
                (b, d) = (d, b);
            }

            a = _mm_add_epi32(a, saves[0]);
            b = _mm_add_epi32(b, saves[1]);
            c = _mm_add_epi32(c, saves[2]);
            d = _mm_add_epi32(d, saves[3]);

            _mm_storeu_si128(output.as_mut_ptr().add(pos).cast(), a);
            _mm_storeu_si128(output.as_mut_ptr().add(pos + 16).cast(), b);
            _mm_storeu_si128(output.as_mut_ptr().add(pos + 32).cast(), c);
            _mm_storeu_si128(output.as_mut_ptr().add(pos + 48).cast(), d);
        }
    }
}

fn xor(x: &[u8], y: &[u8], output: &mut [u8]) {
    for ((out, &x_i), &y_i) in output.iter_mut().zip(x.iter()).zip(y.iter()) {
        *out = x_i ^ y_i;
    }
}
