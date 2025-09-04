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
    dst.copy_from(src, count);
}

pub(crate) unsafe fn blkxor(mut dst: *mut u32, mut src: *const u32, mut count: usize) {
    for i in 0..count {
        *dst.add(i) ^= *src.add(i);
    }
}

pub(crate) unsafe fn integerify(mut B: *const u32, mut r: usize) -> u64 {
    let mut X: *const u32 = B.add(
        (2usize)
            .wrapping_mul(r)
            .wrapping_sub(1usize)
            .wrapping_mul(16usize),
    );
    ((*X.add(13) as u64) << 32).wrapping_add(*X as u64)
}

#[inline]
pub(crate) unsafe fn le32dec(mut pp: *const u32) -> u32 {
    u32::from_le_bytes(pp.cast::<[u8; 4]>().read())
}

#[inline]
pub(crate) unsafe fn le32enc(mut pp: *mut u32, mut x: u32) {
    pp.cast::<[u8; 4]>().write(x.to_le_bytes());
}

unsafe fn memxor(mut dst: *mut u8, mut src: *mut u8, mut size: usize) {
    for i in 0..size {
        *dst.add(i) ^= *src.add(i);
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
