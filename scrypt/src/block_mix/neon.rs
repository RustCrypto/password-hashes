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
    use core::arch::aarch64::*;

    macro_rules! vrol_u32 {
        ($w:expr, $amt:literal) => {{
            let w = $w;
            vsraq_n_u32(vshlq_n_u32(w, $amt), w, 32 - $amt)
        }};
    }

    let last_block = &input[input.len() - 64..];

    let mut a = unsafe { vld1q_u32(last_block.as_ptr().cast()) };
    let mut b = unsafe { vld1q_u32(last_block.as_ptr().add(16).cast()) };
    let mut c = unsafe { vld1q_u32(last_block.as_ptr().add(32).cast()) };
    let mut d = unsafe { vld1q_u32(last_block.as_ptr().add(48).cast()) };

    for (i, chunk) in input.chunks(64).enumerate() {
        let pos = if i % 2 == 0 {
            (i / 2) * 64
        } else {
            (i / 2) * 64 + input.len() / 2
        };

        unsafe {
            let chunk_a = vld1q_u32(chunk.as_ptr().cast());
            let chunk_b = vld1q_u32(chunk.as_ptr().add(16).cast());
            let chunk_c = vld1q_u32(chunk.as_ptr().add(32).cast());
            let chunk_d = vld1q_u32(chunk.as_ptr().add(48).cast());

            a = veorq_u32(a, chunk_a);
            b = veorq_u32(b, chunk_b);
            c = veorq_u32(c, chunk_c);
            d = veorq_u32(d, chunk_d);

            let saves = [a, b, c, d];

            for _ in 0..8 {
                b = veorq_u32(b, vrol_u32!(vaddq_u32(a, d), 7));
                c = veorq_u32(c, vrol_u32!(vaddq_u32(b, a), 9));
                d = veorq_u32(d, vrol_u32!(vaddq_u32(c, b), 13));
                a = veorq_u32(a, vrol_u32!(vaddq_u32(d, c), 18));

                d = vextq_u32(d, d, 1);
                c = vextq_u32(c, c, 2);
                b = vextq_u32(b, b, 3);

                (b, d) = (d, b);
            }

            a = vaddq_u32(a, saves[0]);
            b = vaddq_u32(b, saves[1]);
            c = vaddq_u32(c, saves[2]);
            d = vaddq_u32(d, saves[3]);

            vst1q_u32(output.as_mut_ptr().add(pos).cast(), a);
            vst1q_u32(output.as_mut_ptr().add(pos + 16).cast(), b);
            vst1q_u32(output.as_mut_ptr().add(pos + 32).cast(), c);
            vst1q_u32(output.as_mut_ptr().add(pos + 48).cast(), d);
        }
    }
}
