pub(crate) unsafe fn blkcpy(dst: *mut u32, src: *const u32, count: usize) {
    dst.copy_from(src, count);
}

pub(crate) unsafe fn blkxor(dst: *mut u32, src: *const u32, count: usize) {
    for i in 0..count {
        *dst.add(i) ^= *src.add(i);
    }
}

pub(crate) unsafe fn integerify(b: *const u32, r: usize) -> u64 {
    let x: *const u32 = b.add(
        (2usize)
            .wrapping_mul(r)
            .wrapping_sub(1usize)
            .wrapping_mul(16usize),
    );
    ((*x.add(13) as u64) << 32).wrapping_add(*x as u64)
}

pub(crate) fn prev_power_of_two(mut x: u64) -> u64 {
    let mut y;

    loop {
        y = x & x.wrapping_sub(1);
        if y == 0 {
            break;
        }
        x = y;
    }
    x
}
