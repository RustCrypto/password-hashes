#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]

pub(crate) unsafe fn blkcpy(mut dst: *mut u32, mut src: *const u32, mut count: usize) {
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

pub(crate) unsafe fn blkxor(mut dst: *mut u32, mut src: *const u32, mut count: usize) {
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

pub(crate) unsafe fn integerify(mut B: *const u32, mut r: usize) -> u64 {
    let mut X: *const u32 = &*B.offset(
        (2usize)
            .wrapping_mul(r)
            .wrapping_sub(1usize)
            .wrapping_mul(16usize) as isize,
    ) as *const u32;
    return ((*X.offset(13 as libc::c_int as isize) as u64) << 32 as libc::c_int)
        .wrapping_add(*X.offset(0 as libc::c_int as isize) as libc::c_ulong);
}

#[inline]
pub(crate) unsafe fn le32dec(mut pp: *const u32) -> u32 {
    u32::from_le_bytes(pp.cast::<[u8; 4]>().read())
}

#[inline]
pub(crate) unsafe fn le32enc(mut pp: *mut u32, mut x: u32) {
    pp.cast::<[u8; 4]>().write(x.to_le_bytes());
}

unsafe fn memxor(mut dst: *mut libc::c_uchar, mut src: *mut libc::c_uchar, mut size: usize) {
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

pub(crate) fn wrap(mut x: u64, mut i: u64) -> u64 {
    let mut n: u64 = prev_power_of_two(i);
    (x & n.wrapping_sub(1)).wrapping_add(i.wrapping_sub(n))
}
