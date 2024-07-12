use crate::{
    common::{blkcpy, blkxor},
    size_t, uint32_t,
};

pub(crate) unsafe fn salsa20(mut B: *mut uint32_t, mut rounds: uint32_t) {
    let mut x: [uint32_t; 16] = [0; 16];
    for i in 0..16 {
        x[i * 5 % 16] = *B.offset(i as isize);
    }

    use salsa20::cipher::StreamCipherCore;

    let mut block = [0u8; 64];

    if rounds == 2 {
        salsa20::SalsaCore::<salsa20::cipher::consts::U1>::from_raw_state(x)
            .write_keystream_block((&mut block).into());
    } else if rounds == 8 {
        salsa20::SalsaCore::<salsa20::cipher::consts::U4>::from_raw_state(x)
            .write_keystream_block((&mut block).into());
    }

    for (c, b) in block.chunks_exact(4).zip(x.iter_mut()) {
        *b = u32::from_le_bytes(c.try_into().expect("4 bytes is 1 u32")).wrapping_sub(*b);
    }

    for i in 0..16 {
        let x = (*B.offset(i as isize)).wrapping_add(x[i * 5 % 16]);
        B.offset(i as isize).write(x)
    }
}

pub(crate) unsafe fn blockmix_salsa8(mut B: *mut uint32_t, mut Y: *mut uint32_t, mut r: size_t) {
    let mut X: [uint32_t; 16] = [0; 16];
    let mut i: size_t = 0;
    blkcpy(
        X.as_mut_ptr(),
        &mut *B.offset(
            (2 as libc::c_int as libc::c_ulong)
                .wrapping_mul(r)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                .wrapping_mul(16 as libc::c_int as libc::c_ulong) as isize,
        ),
        16 as libc::c_int as size_t,
    );
    i = 0 as libc::c_int as size_t;
    while i < (2 as libc::c_int as libc::c_ulong).wrapping_mul(r) {
        blkxor(
            X.as_mut_ptr(),
            &mut *B.offset(i.wrapping_mul(16 as libc::c_int as libc::c_ulong) as isize),
            16 as libc::c_int as size_t,
        );
        salsa20(X.as_mut_ptr(), 8);
        blkcpy(
            &mut *Y.offset(i.wrapping_mul(16 as libc::c_int as libc::c_ulong) as isize),
            X.as_mut_ptr(),
            16 as libc::c_int as size_t,
        );
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as size_t;
    while i < r {
        blkcpy(
            &mut *B.offset(i.wrapping_mul(16 as libc::c_int as libc::c_ulong) as isize),
            &mut *Y.offset(
                i.wrapping_mul(2 as libc::c_int as libc::c_ulong)
                    .wrapping_mul(16 as libc::c_int as libc::c_ulong) as isize,
            ),
            16 as libc::c_int as size_t,
        );
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as size_t;
    while i < r {
        blkcpy(
            &mut *B.offset(
                i.wrapping_add(r)
                    .wrapping_mul(16 as libc::c_int as libc::c_ulong) as isize,
            ),
            &mut *Y.offset(
                i.wrapping_mul(2 as libc::c_int as libc::c_ulong)
                    .wrapping_add(1 as libc::c_int as libc::c_ulong)
                    .wrapping_mul(16 as libc::c_int as libc::c_ulong) as isize,
            ),
            16 as libc::c_int as size_t,
        );
        i = i.wrapping_add(1);
        i;
    }
}
