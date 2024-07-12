use salsa20::cipher::Unsigned;

use crate::{
    common::{blkcpy, blkxor},
    size_t, uint32_t,
};

pub(crate) unsafe fn salsa20_2(mut B: *mut uint32_t) {
    salsa20::<salsa20::cipher::consts::U1>(B);
}

unsafe fn salsa20<R: Unsigned>(mut B: *mut uint32_t) {
    let mut x: [uint32_t; 16] = [0; 16];
    for i in 0..16 {
        x[i * 5 % 16] = *B.offset(i as isize);
    }

    use salsa20::cipher::StreamCipherCore;

    let mut block = [0u8; 64];
    salsa20::SalsaCore::<R>::from_raw_state(x).write_keystream_block((&mut block).into());

    for (c, b) in block.chunks_exact(4).zip(x.iter_mut()) {
        *b = u32::from_le_bytes(c.try_into().expect("4 bytes is 1 u32")).wrapping_sub(*b);
    }

    for i in 0..16 {
        let x = (*B.offset(i as isize)).wrapping_add(x[i * 5 % 16]);
        B.offset(i as isize).write(x)
    }
}

pub(crate) unsafe fn blockmix_salsa8(mut B: *mut uint32_t, mut Y: *mut uint32_t, mut r: usize) {
    let mut X: [uint32_t; 16] = [0; 16];
    blkcpy(X.as_mut_ptr(), &mut *B.add((2 * r - 1) * 16), 16);
    for i in 0..(2 * r) {
        blkxor(X.as_mut_ptr(), &mut *B.add(i * 16), 16);
        salsa20::<salsa20::cipher::consts::U4>(X.as_mut_ptr());
        blkcpy(&mut *Y.add(i * 16), X.as_mut_ptr(), 16);
    }
    for i in 0..r {
        blkcpy(&mut *B.add(i * 16), &mut *Y.add((i * 2) * 16), 16);
    }
    for i in 0..r {
        blkcpy(&mut *B.add((i + r) * 16), &mut *Y.add((i * 2 + 1) * 16), 16);
    }
}
