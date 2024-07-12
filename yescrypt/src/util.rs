//! Utility functions.
// TODO(tarcieri): replace these with idiomatic Rust

use crate::{size_t, uint32_t, uint64_t, uint8_t};

#[inline]
pub(crate) unsafe fn le32dec(mut pp: *const libc::c_void) -> uint32_t {
    let mut p: *const uint8_t = pp as *const uint8_t;
    return (*p.offset(0 as libc::c_int as isize) as uint32_t)
        .wrapping_add((*p.offset(1 as libc::c_int as isize) as uint32_t) << 8 as libc::c_int)
        .wrapping_add((*p.offset(2 as libc::c_int as isize) as uint32_t) << 16 as libc::c_int)
        .wrapping_add((*p.offset(3 as libc::c_int as isize) as uint32_t) << 24 as libc::c_int);
}

#[inline]
pub(crate) unsafe fn le32enc(mut pp: *mut libc::c_void, mut x: uint32_t) {
    let mut p: *mut uint8_t = pp as *mut uint8_t;
    *p.offset(0 as libc::c_int as isize) = (x & 0xff as libc::c_int as libc::c_uint) as uint8_t;
    *p.offset(1 as libc::c_int as isize) =
        (x >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as uint8_t;
    *p.offset(2 as libc::c_int as isize) =
        (x >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as uint8_t;
    *p.offset(3 as libc::c_int as isize) =
        (x >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as uint8_t;
}

pub(crate) unsafe fn blkcpy(mut dst: *mut uint32_t, mut src: *const uint32_t, mut count: size_t) {
    loop {
        let fresh0 = src;
        src = src.offset(1);
        let fresh1 = dst;
        dst = dst.offset(1);
        *fresh1 = *fresh0;
        count = count.wrapping_sub(1);
        if !(count != 0) {
            break;
        }
    }
}

pub(crate) unsafe fn blkxor(mut dst: *mut uint32_t, mut src: *const uint32_t, mut count: size_t) {
    loop {
        let fresh2 = src;
        src = src.offset(1);
        let fresh3 = dst;
        dst = dst.offset(1);
        *fresh3 ^= *fresh2;
        count = count.wrapping_sub(1);
        if !(count != 0) {
            break;
        }
    }
}

pub(crate) unsafe fn integerify(mut B: *const uint32_t, mut r: size_t) -> uint64_t {
    let mut X: *const uint32_t = &*B.offset(
        (2 as libc::c_int as libc::c_ulong)
            .wrapping_mul(r)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_mul(16 as libc::c_int as libc::c_ulong) as isize,
    ) as *const uint32_t;
    return ((*X.offset(13 as libc::c_int as isize) as uint64_t) << 32 as libc::c_int)
        .wrapping_add(*X.offset(0 as libc::c_int as isize) as libc::c_ulong);
}

pub(crate) unsafe fn p2floor(mut x: uint64_t) -> uint64_t {
    let mut y: uint64_t = 0;
    loop {
        y = x & x.wrapping_sub(1 as libc::c_int as libc::c_ulong);
        if !(y != 0) {
            break;
        }
        x = y;
    }
    return x;
}

pub(crate) unsafe fn wrap(mut x: uint64_t, mut i: uint64_t) -> uint64_t {
    let mut n: uint64_t = p2floor(i);
    return (x & n.wrapping_sub(1 as libc::c_int as libc::c_ulong)).wrapping_add(i.wrapping_sub(n));
}
