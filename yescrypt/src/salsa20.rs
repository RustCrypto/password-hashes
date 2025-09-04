use salsa20::cipher::typenum::Unsigned;

use crate::common::{blkcpy, blkxor};

pub(crate) unsafe fn salsa20_2(B: *mut u32) {
    salsa20::<salsa20::cipher::consts::U1>(B);
}

unsafe fn salsa20<R: Unsigned>(B: *mut u32) {
    let mut x: [u32; 16] = [0; 16];
    for i in 0..16 {
        x[i * 5 % 16] = *B.add(i);
    }

    use salsa20::cipher::StreamCipherCore;

    let mut block = [0u8; 64];
    salsa20::SalsaCore::<R>::from_raw_state(x).write_keystream_block((&mut block).into());

    for (c, b) in block.chunks_exact(4).zip(x.iter_mut()) {
        *b = u32::from_le_bytes(c.try_into().expect("4 bytes is 1 u32")).wrapping_sub(*b);
    }

    for i in 0..16 {
        let x = (*B.add(i)).wrapping_add(x[i * 5 % 16]);
        B.add(i).write(x)
    }
}

pub(crate) unsafe fn blockmix_salsa8(B: *mut u32, Y: *mut u32, r: usize) {
    let mut X: [u32; 16] = [0; 16];
    blkcpy(X.as_mut_ptr(), B.add((2 * r - 1) * 16), 16);
    for i in 0..(2 * r) {
        blkxor(X.as_mut_ptr(), B.add(i * 16), 16);
        salsa20::<salsa20::cipher::consts::U4>(X.as_mut_ptr());
        blkcpy(Y.add(i * 16), X.as_mut_ptr(), 16);
    }
    for i in 0..r {
        blkcpy(B.add(i * 16), Y.add((i * 2) * 16), 16);
    }
    for i in 0..r {
        blkcpy(B.add((i + r) * 16), Y.add((i * 2 + 1) * 16), 16);
    }
}
