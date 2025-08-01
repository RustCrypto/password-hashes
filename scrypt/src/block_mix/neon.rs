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

    let mut x = unsafe { vld1q_u32_x4(last_block.as_ptr().cast()) };

    for (i, chunk) in input.chunks(64).enumerate() {
        let pos = if i % 2 == 0 {
            (i / 2) * 64
        } else {
            (i / 2) * 64 + input.len() / 2
        };

        unsafe {
            let chunk = vld1q_u32_x4(chunk.as_ptr().cast());

            x.0 = veorq_u32(x.0, chunk.0);
            x.1 = veorq_u32(x.1, chunk.1);
            x.2 = veorq_u32(x.2, chunk.2);
            x.3 = veorq_u32(x.3, chunk.3);

            let mut a = x.0;
            let mut b = x.1;
            let mut c = x.2;
            let mut d = x.3;

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

            x.0 = vaddq_u32(x.0, a);
            x.1 = vaddq_u32(x.1, b);
            x.2 = vaddq_u32(x.2, c);
            x.3 = vaddq_u32(x.3, d);

            vst1q_u32_x4(output.as_mut_ptr().add(pos).cast(), x);
        }
    }
}
