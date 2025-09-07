//! Wrapper functions for invoking the `salsa20` crate.

use crate::util::{slice_as_chunks_mut, xor};
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
    // TODO(tarcieri): use upstream `[T]::as_chunks_mut` when MSRV is 1.88
    let (b, _) = slice_as_chunks_mut::<_, 16>(b);
    let (y, _) = slice_as_chunks_mut::<_, 16>(y);
    let mut x = b[2 * r - 1];

    for i in 0..(2 * r) {
        xor(&mut x, &b[i]);
        salsa20::<U4>(&mut x);
        y[i].copy_from_slice(&x);
    }

    for i in 0..r {
        b[i].copy_from_slice(&y[i * 2]);
    }

    for i in 0..r {
        b[i + r].copy_from_slice(&y[i * 2 + 1]);
    }
}
