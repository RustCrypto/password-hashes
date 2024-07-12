use crate::{
    size_t, uint32_t,
    util::{blkcpy, blkxor},
};

pub(crate) unsafe fn salsa20(mut B: *mut uint32_t, mut rounds: uint32_t) {
    let mut x: [uint32_t; 16] = [0; 16];
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < 16 as libc::c_int as libc::c_ulong {
        x[i.wrapping_mul(5 as libc::c_int as libc::c_ulong)
            .wrapping_rem(16 as libc::c_int as libc::c_ulong) as usize] = *B.offset(i as isize);
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as size_t;
    while i < rounds as libc::c_ulong {
        x[4 as libc::c_int as usize] ^= (x[0 as libc::c_int as usize])
            .wrapping_add(x[12 as libc::c_int as usize])
            << 7 as libc::c_int
            | (x[0 as libc::c_int as usize]).wrapping_add(x[12 as libc::c_int as usize])
                >> 32 as libc::c_int - 7 as libc::c_int;
        x[8 as libc::c_int as usize] ^= (x[4 as libc::c_int as usize])
            .wrapping_add(x[0 as libc::c_int as usize])
            << 9 as libc::c_int
            | (x[4 as libc::c_int as usize]).wrapping_add(x[0 as libc::c_int as usize])
                >> 32 as libc::c_int - 9 as libc::c_int;
        x[12 as libc::c_int as usize] ^= (x[8 as libc::c_int as usize])
            .wrapping_add(x[4 as libc::c_int as usize])
            << 13 as libc::c_int
            | (x[8 as libc::c_int as usize]).wrapping_add(x[4 as libc::c_int as usize])
                >> 32 as libc::c_int - 13 as libc::c_int;
        x[0 as libc::c_int as usize] ^= (x[12 as libc::c_int as usize])
            .wrapping_add(x[8 as libc::c_int as usize])
            << 18 as libc::c_int
            | (x[12 as libc::c_int as usize]).wrapping_add(x[8 as libc::c_int as usize])
                >> 32 as libc::c_int - 18 as libc::c_int;
        x[9 as libc::c_int as usize] ^= (x[5 as libc::c_int as usize])
            .wrapping_add(x[1 as libc::c_int as usize])
            << 7 as libc::c_int
            | (x[5 as libc::c_int as usize]).wrapping_add(x[1 as libc::c_int as usize])
                >> 32 as libc::c_int - 7 as libc::c_int;
        x[13 as libc::c_int as usize] ^= (x[9 as libc::c_int as usize])
            .wrapping_add(x[5 as libc::c_int as usize])
            << 9 as libc::c_int
            | (x[9 as libc::c_int as usize]).wrapping_add(x[5 as libc::c_int as usize])
                >> 32 as libc::c_int - 9 as libc::c_int;
        x[1 as libc::c_int as usize] ^= (x[13 as libc::c_int as usize])
            .wrapping_add(x[9 as libc::c_int as usize])
            << 13 as libc::c_int
            | (x[13 as libc::c_int as usize]).wrapping_add(x[9 as libc::c_int as usize])
                >> 32 as libc::c_int - 13 as libc::c_int;
        x[5 as libc::c_int as usize] ^= (x[1 as libc::c_int as usize])
            .wrapping_add(x[13 as libc::c_int as usize])
            << 18 as libc::c_int
            | (x[1 as libc::c_int as usize]).wrapping_add(x[13 as libc::c_int as usize])
                >> 32 as libc::c_int - 18 as libc::c_int;
        x[14 as libc::c_int as usize] ^= (x[10 as libc::c_int as usize])
            .wrapping_add(x[6 as libc::c_int as usize])
            << 7 as libc::c_int
            | (x[10 as libc::c_int as usize]).wrapping_add(x[6 as libc::c_int as usize])
                >> 32 as libc::c_int - 7 as libc::c_int;
        x[2 as libc::c_int as usize] ^= (x[14 as libc::c_int as usize])
            .wrapping_add(x[10 as libc::c_int as usize])
            << 9 as libc::c_int
            | (x[14 as libc::c_int as usize]).wrapping_add(x[10 as libc::c_int as usize])
                >> 32 as libc::c_int - 9 as libc::c_int;
        x[6 as libc::c_int as usize] ^= (x[2 as libc::c_int as usize])
            .wrapping_add(x[14 as libc::c_int as usize])
            << 13 as libc::c_int
            | (x[2 as libc::c_int as usize]).wrapping_add(x[14 as libc::c_int as usize])
                >> 32 as libc::c_int - 13 as libc::c_int;
        x[10 as libc::c_int as usize] ^= (x[6 as libc::c_int as usize])
            .wrapping_add(x[2 as libc::c_int as usize])
            << 18 as libc::c_int
            | (x[6 as libc::c_int as usize]).wrapping_add(x[2 as libc::c_int as usize])
                >> 32 as libc::c_int - 18 as libc::c_int;
        x[3 as libc::c_int as usize] ^= (x[15 as libc::c_int as usize])
            .wrapping_add(x[11 as libc::c_int as usize])
            << 7 as libc::c_int
            | (x[15 as libc::c_int as usize]).wrapping_add(x[11 as libc::c_int as usize])
                >> 32 as libc::c_int - 7 as libc::c_int;
        x[7 as libc::c_int as usize] ^= (x[3 as libc::c_int as usize])
            .wrapping_add(x[15 as libc::c_int as usize])
            << 9 as libc::c_int
            | (x[3 as libc::c_int as usize]).wrapping_add(x[15 as libc::c_int as usize])
                >> 32 as libc::c_int - 9 as libc::c_int;
        x[11 as libc::c_int as usize] ^= (x[7 as libc::c_int as usize])
            .wrapping_add(x[3 as libc::c_int as usize])
            << 13 as libc::c_int
            | (x[7 as libc::c_int as usize]).wrapping_add(x[3 as libc::c_int as usize])
                >> 32 as libc::c_int - 13 as libc::c_int;
        x[15 as libc::c_int as usize] ^= (x[11 as libc::c_int as usize])
            .wrapping_add(x[7 as libc::c_int as usize])
            << 18 as libc::c_int
            | (x[11 as libc::c_int as usize]).wrapping_add(x[7 as libc::c_int as usize])
                >> 32 as libc::c_int - 18 as libc::c_int;
        x[1 as libc::c_int as usize] ^= (x[0 as libc::c_int as usize])
            .wrapping_add(x[3 as libc::c_int as usize])
            << 7 as libc::c_int
            | (x[0 as libc::c_int as usize]).wrapping_add(x[3 as libc::c_int as usize])
                >> 32 as libc::c_int - 7 as libc::c_int;
        x[2 as libc::c_int as usize] ^= (x[1 as libc::c_int as usize])
            .wrapping_add(x[0 as libc::c_int as usize])
            << 9 as libc::c_int
            | (x[1 as libc::c_int as usize]).wrapping_add(x[0 as libc::c_int as usize])
                >> 32 as libc::c_int - 9 as libc::c_int;
        x[3 as libc::c_int as usize] ^= (x[2 as libc::c_int as usize])
            .wrapping_add(x[1 as libc::c_int as usize])
            << 13 as libc::c_int
            | (x[2 as libc::c_int as usize]).wrapping_add(x[1 as libc::c_int as usize])
                >> 32 as libc::c_int - 13 as libc::c_int;
        x[0 as libc::c_int as usize] ^= (x[3 as libc::c_int as usize])
            .wrapping_add(x[2 as libc::c_int as usize])
            << 18 as libc::c_int
            | (x[3 as libc::c_int as usize]).wrapping_add(x[2 as libc::c_int as usize])
                >> 32 as libc::c_int - 18 as libc::c_int;
        x[6 as libc::c_int as usize] ^= (x[5 as libc::c_int as usize])
            .wrapping_add(x[4 as libc::c_int as usize])
            << 7 as libc::c_int
            | (x[5 as libc::c_int as usize]).wrapping_add(x[4 as libc::c_int as usize])
                >> 32 as libc::c_int - 7 as libc::c_int;
        x[7 as libc::c_int as usize] ^= (x[6 as libc::c_int as usize])
            .wrapping_add(x[5 as libc::c_int as usize])
            << 9 as libc::c_int
            | (x[6 as libc::c_int as usize]).wrapping_add(x[5 as libc::c_int as usize])
                >> 32 as libc::c_int - 9 as libc::c_int;
        x[4 as libc::c_int as usize] ^= (x[7 as libc::c_int as usize])
            .wrapping_add(x[6 as libc::c_int as usize])
            << 13 as libc::c_int
            | (x[7 as libc::c_int as usize]).wrapping_add(x[6 as libc::c_int as usize])
                >> 32 as libc::c_int - 13 as libc::c_int;
        x[5 as libc::c_int as usize] ^= (x[4 as libc::c_int as usize])
            .wrapping_add(x[7 as libc::c_int as usize])
            << 18 as libc::c_int
            | (x[4 as libc::c_int as usize]).wrapping_add(x[7 as libc::c_int as usize])
                >> 32 as libc::c_int - 18 as libc::c_int;
        x[11 as libc::c_int as usize] ^= (x[10 as libc::c_int as usize])
            .wrapping_add(x[9 as libc::c_int as usize])
            << 7 as libc::c_int
            | (x[10 as libc::c_int as usize]).wrapping_add(x[9 as libc::c_int as usize])
                >> 32 as libc::c_int - 7 as libc::c_int;
        x[8 as libc::c_int as usize] ^= (x[11 as libc::c_int as usize])
            .wrapping_add(x[10 as libc::c_int as usize])
            << 9 as libc::c_int
            | (x[11 as libc::c_int as usize]).wrapping_add(x[10 as libc::c_int as usize])
                >> 32 as libc::c_int - 9 as libc::c_int;
        x[9 as libc::c_int as usize] ^= (x[8 as libc::c_int as usize])
            .wrapping_add(x[11 as libc::c_int as usize])
            << 13 as libc::c_int
            | (x[8 as libc::c_int as usize]).wrapping_add(x[11 as libc::c_int as usize])
                >> 32 as libc::c_int - 13 as libc::c_int;
        x[10 as libc::c_int as usize] ^= (x[9 as libc::c_int as usize])
            .wrapping_add(x[8 as libc::c_int as usize])
            << 18 as libc::c_int
            | (x[9 as libc::c_int as usize]).wrapping_add(x[8 as libc::c_int as usize])
                >> 32 as libc::c_int - 18 as libc::c_int;
        x[12 as libc::c_int as usize] ^= (x[15 as libc::c_int as usize])
            .wrapping_add(x[14 as libc::c_int as usize])
            << 7 as libc::c_int
            | (x[15 as libc::c_int as usize]).wrapping_add(x[14 as libc::c_int as usize])
                >> 32 as libc::c_int - 7 as libc::c_int;
        x[13 as libc::c_int as usize] ^= (x[12 as libc::c_int as usize])
            .wrapping_add(x[15 as libc::c_int as usize])
            << 9 as libc::c_int
            | (x[12 as libc::c_int as usize]).wrapping_add(x[15 as libc::c_int as usize])
                >> 32 as libc::c_int - 9 as libc::c_int;
        x[14 as libc::c_int as usize] ^= (x[13 as libc::c_int as usize])
            .wrapping_add(x[12 as libc::c_int as usize])
            << 13 as libc::c_int
            | (x[13 as libc::c_int as usize]).wrapping_add(x[12 as libc::c_int as usize])
                >> 32 as libc::c_int - 13 as libc::c_int;
        x[15 as libc::c_int as usize] ^= (x[14 as libc::c_int as usize])
            .wrapping_add(x[13 as libc::c_int as usize])
            << 18 as libc::c_int
            | (x[14 as libc::c_int as usize]).wrapping_add(x[13 as libc::c_int as usize])
                >> 32 as libc::c_int - 18 as libc::c_int;
        i = (i as libc::c_ulong).wrapping_add(2 as libc::c_int as libc::c_ulong) as size_t
            as size_t;
    }
    i = 0 as libc::c_int as size_t;
    while i < 16 as libc::c_int as libc::c_ulong {
        let ref mut fresh4 = *B.offset(i as isize);
        *fresh4 = (*fresh4 as libc::c_uint).wrapping_add(
            x[i.wrapping_mul(5 as libc::c_int as libc::c_ulong)
                .wrapping_rem(16 as libc::c_int as libc::c_ulong) as usize],
        ) as uint32_t as uint32_t;
        i = i.wrapping_add(1);
        i;
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
        salsa20(X.as_mut_ptr(), 8 as libc::c_int as uint32_t);
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
