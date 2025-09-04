#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]

use crate::{size_t, uint32_t, uint64_t};

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

pub(crate) unsafe fn integerify(mut B: *const uint32_t, mut r: usize) -> uint64_t {
    let mut X: *const uint32_t = &*B.offset(
        (2usize)
            .wrapping_mul(r)
            .wrapping_sub(1usize)
            .wrapping_mul(16usize) as isize,
    ) as *const uint32_t;
    return ((*X.offset(13 as libc::c_int as isize) as uint64_t) << 32 as libc::c_int)
        .wrapping_add(*X.offset(0 as libc::c_int as isize) as libc::c_ulong);
}

#[inline]
pub(crate) unsafe fn le32dec(mut pp: *const u32) -> uint32_t {
    u32::from_le_bytes(pp.cast::<[u8; 4]>().read())
}

#[inline]
pub(crate) unsafe fn le32enc(mut pp: *mut u32, mut x: uint32_t) {
    pp.cast::<[u8; 4]>().write(x.to_le_bytes());
}

unsafe fn memxor(mut dst: *mut libc::c_uchar, mut src: *mut libc::c_uchar, mut size: size_t) {
    loop {
        let fresh10 = size;
        size = size.wrapping_sub(1);
        if !(fresh10 != 0) {
            break;
        }
        let fresh11 = src;
        src = src.offset(1);
        let fresh12 = dst;
        dst = dst.offset(1);
        *fresh12 = (*fresh12 as libc::c_int ^ *fresh11 as libc::c_int) as libc::c_uchar;
    }
}

pub(crate) fn prev_power_of_two(mut x: u64) -> u64 {
    let mut y = 0;
    loop {
        y = x & x.wrapping_sub(1);
        if y == 0 {
            break;
        }
        x = y;
    }
    x
}

pub(crate) fn wrap(mut x: uint64_t, mut i: uint64_t) -> uint64_t {
    let mut n: uint64_t = prev_power_of_two(i);
    (x & n.wrapping_sub(1)).wrapping_add(i.wrapping_sub(n))
}
