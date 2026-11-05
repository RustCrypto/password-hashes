//! Wrapper functions for invoking the `salsa20` crate.

use crate::xor;
use salsa20::cipher::{
    StreamCipherCore,
    consts::{U1, U4},
    typenum::Unsigned,
};

pub(crate) fn salsa20_2(b: &mut [u32; 16]) {
    salsa20::<U1>(b);
}

fn salsa20<R: Unsigned>(b: &mut [u32; 16]) {
    let mut x = [0u32; 16];

    for i in 0..16 {
        x[i * 5 % 16] = b[i];
    }

    let mut block = [0u8; 64];
    salsa20::SalsaCore::<R>::from_raw_state(x).write_keystream_block((&mut block).into());

    for (c, b) in block.chunks_exact(4).zip(x.iter_mut()) {
        *b = u32::from_le_bytes(c.try_into().expect("4 bytes is 1 u32")).wrapping_sub(*b);
    }

    for i in 0..16 {
        b[i] = b[i].wrapping_add(x[i * 5 % 16]);
    }
}

pub(crate) fn blockmix_salsa8(b: &mut [u32], y: &mut [u32], r: usize) {
    let b = &mut b[..32 * r];
    let y = &mut y[..32 * r];
    let mut x = *b.last_chunk::<16>().expect("B contains 2r blocks");

    for (bi, yi) in b.chunks_exact(16).zip(y.chunks_exact_mut(16)) {
        xor(&mut x, bi);
        salsa20::<U4>(&mut x);
        yi.copy_from_slice(&x);
    }

    let (b0, b1) = b.split_at_mut(16 * r);

    for ((b0, b1), yi) in b0
        .chunks_exact_mut(16)
        .zip(b1.chunks_exact_mut(16))
        .zip(y.chunks_exact(32))
    {
        b0.copy_from_slice(&yi[..16]);
        b1.copy_from_slice(&yi[16..]);
    }
}
