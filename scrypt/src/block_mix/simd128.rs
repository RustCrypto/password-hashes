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
    use core::arch::wasm32::*;

    macro_rules! u32x4_rol {
        ($w:expr, $amt:literal) => {{
            let w = $w;
            v128_or(u32x4_shl(w, $amt), u32x4_shr(w, 32 - $amt))
        }};
    }

    let last_block = &input[input.len() - 64..];

    let mut a = unsafe { v128_load(last_block.as_ptr().cast()) };
    let mut b = unsafe { v128_load(last_block.as_ptr().add(16).cast()) };
    let mut c = unsafe { v128_load(last_block.as_ptr().add(32).cast()) };
    let mut d = unsafe { v128_load(last_block.as_ptr().add(48).cast()) };

    for (i, chunk) in input.chunks(64).enumerate() {
        let pos = if i % 2 == 0 {
            (i / 2) * 64
        } else {
            (i / 2) * 64 + input.len() / 2
        };

        unsafe {
            let chunk_a = v128_load(chunk.as_ptr().cast());
            let chunk_b = v128_load(chunk.as_ptr().add(16).cast());
            let chunk_c = v128_load(chunk.as_ptr().add(32).cast());
            let chunk_d = v128_load(chunk.as_ptr().add(48).cast());

            a = v128_xor(a, chunk_a);
            b = v128_xor(b, chunk_b);
            c = v128_xor(c, chunk_c);
            d = v128_xor(d, chunk_d);

            let saves = [a, b, c, d];

            for _ in 0..8 {
                b = v128_xor(b, u32x4_rol!(u32x4_add(a, d), 7));
                c = v128_xor(c, u32x4_rol!(u32x4_add(b, a), 9));
                d = v128_xor(d, u32x4_rol!(u32x4_add(c, b), 13));
                a = v128_xor(a, u32x4_rol!(u32x4_add(d, c), 18));

                d = i32x4_shuffle::<1, 2, 3, 0>(d, d);
                c = i32x4_shuffle::<2, 3, 0, 1>(c, c);
                b = i32x4_shuffle::<3, 0, 1, 2>(b, b);

                (b, d) = (d, b);
            }

            a = u32x4_add(a, saves[0]);
            b = u32x4_add(b, saves[1]);
            c = u32x4_add(c, saves[2]);
            d = u32x4_add(d, saves[3]);

            v128_store(output.as_mut_ptr().add(pos).cast(), a);
            v128_store(output.as_mut_ptr().add(pos + 16).cast(), b);
            v128_store(output.as_mut_ptr().add(pos + 32).cast(), c);
            v128_store(output.as_mut_ptr().add(pos + 48).cast(), d);
        }
    }
}
