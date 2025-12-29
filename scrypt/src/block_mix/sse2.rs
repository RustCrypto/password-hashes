use crate::block_mix::pivot::{INVERSE_PIVOT_ABCD, PIVOT_ABCD};

pub(crate) fn shuffle_in(b: &mut [u8]) {
    for chunk in b.chunks_exact_mut(64) {
        let mut t = [0u32; 16];
        for (c, b) in chunk.chunks_exact(4).zip(t.iter_mut()) {
            *b = u32::from_ne_bytes(c.try_into().unwrap());
        }
        chunk.chunks_exact_mut(4).enumerate().for_each(|(i, b)| {
            b.copy_from_slice(&t[PIVOT_ABCD[i]].to_ne_bytes());
        });
    }
}

pub(crate) fn shuffle_out(b: &mut [u8]) {
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

pub(crate) fn scrypt_block_mix(input: &[u8], output: &mut [u8]) {
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

    let last_block = &input[input.len() - 64..];

    let mut a = unsafe { _mm_loadu_si128(last_block.as_ptr().cast()) };
    let mut b = unsafe { _mm_loadu_si128(last_block.as_ptr().add(16).cast()) };
    let mut c = unsafe { _mm_loadu_si128(last_block.as_ptr().add(32).cast()) };
    let mut d = unsafe { _mm_loadu_si128(last_block.as_ptr().add(48).cast()) };

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
