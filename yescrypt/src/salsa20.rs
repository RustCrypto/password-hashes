//! Wrapper functions for invoking the `salsa20` crate.

use crate::common::{blkcpy, blkxor};
use salsa20::cipher::{
    StreamCipherCore,
    consts::{U1, U4},
    typenum::Unsigned,
};

pub(crate) unsafe fn salsa20_2(b: *mut u32) {
    salsa20::<U1>(b);
}

unsafe fn salsa20<R: Unsigned>(b: *mut u32) {
    let mut x = [0u32; 16];

    for i in 0..16 {
        x[i * 5 % 16] = *b.add(i);
    }

    let mut block = [0u8; 64];
    salsa20::SalsaCore::<R>::from_raw_state(x).write_keystream_block((&mut block).into());

    for (c, b) in block.chunks_exact(4).zip(x.iter_mut()) {
        *b = u32::from_le_bytes(c.try_into().expect("4 bytes is 1 u32")).wrapping_sub(*b);
    }

    for i in 0..16 {
        let x = (*b.add(i)).wrapping_add(x[i * 5 % 16]);
        b.add(i).write(x)
    }
}

pub(crate) unsafe fn blockmix_salsa8(b: *mut u32, y: *mut u32, r: usize) {
    let mut x = [0u32; 16];
    blkcpy(x.as_mut_ptr(), b.add((2 * r - 1) * 16), 16);

    for i in 0..(2 * r) {
        blkxor(x.as_mut_ptr(), b.add(i * 16), 16);
        salsa20::<U4>(x.as_mut_ptr());
        blkcpy(y.add(i * 16), x.as_mut_ptr(), 16);
    }

    for i in 0..r {
        blkcpy(b.add(i * 16), y.add((i * 2) * 16), 16);
    }

    for i in 0..r {
        blkcpy(b.add((i + r) * 16), y.add((i * 2 + 1) * 16), 16);
    }
}
