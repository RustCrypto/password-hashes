#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]

use crate::{
    encrypt_dir_t,
    sha256::{SHA256_Final, SHA256_Init, SHA256_Update, SHA256_CTX},
    size_t, Binary, DEC,
};

static mut itoa64: &'static [u8] =
    b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\0";
static mut atoi64_partial: [u8; 77] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 64, 64, 64, 64, 64, 64, 64, 12, 13, 14, 15, 16, 17, 18,
    19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 64, 64, 64, 64, 64,
    64, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
    61, 62, 63,
];

pub(crate) unsafe fn blkcpy(mut dst: *mut u32, mut src: *const u32, mut count: size_t) {
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

pub(crate) unsafe fn blkxor(mut dst: *mut u32, mut src: *const u32, mut count: size_t) {
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

#[inline]
pub(crate) unsafe fn atoi64(mut src: u8) -> u32 {
    if src as libc::c_int >= '.' as i32 && src as libc::c_int <= 'z' as i32 {
        return atoi64_partial[(src as libc::c_int - '.' as i32) as usize] as u32;
    }
    return 64 as libc::c_int as u32;
}

pub(crate) unsafe fn decode64(
    mut dst: *mut u8,
    mut dstlen: *mut size_t,
    mut src: *const u8,
    mut srclen: size_t,
) -> *const u8 {
    let mut current_block: u64;
    let mut dstpos: size_t = 0 as libc::c_int as size_t;
    's_3: loop {
        if !(dstpos <= *dstlen && srclen != 0) {
            current_block = 15904375183555213903;
            break;
        }
        let mut value: u32 = 0 as libc::c_int as u32;
        let mut bits: u32 = 0 as libc::c_int as u32;
        loop {
            let fresh7 = srclen;
            srclen = srclen.wrapping_sub(1);
            if !(fresh7 != 0) {
                break;
            }
            let mut c: u32 = atoi64(*src);
            if c > 63 as libc::c_int as libc::c_uint {
                srclen = 0 as libc::c_int as size_t;
                break;
            } else {
                src = src.offset(1);
                src;
                value |= c << bits;
                bits = (bits as libc::c_uint).wrapping_add(6 as libc::c_int as libc::c_uint) as u32
                    as u32;
                if bits >= 24 as libc::c_int as libc::c_uint {
                    break;
                }
            }
        }
        if bits == 0 {
            current_block = 15904375183555213903;
            break;
        }
        if bits < 12 as libc::c_int as libc::c_uint {
            current_block = 17909480686762627388;
            break;
        } else {
            loop {
                let fresh8 = dstpos;
                dstpos = dstpos.wrapping_add(1);
                if !(fresh8 < *dstlen) {
                    break;
                }
                let fresh9 = dst;
                dst = dst.offset(1);
                *fresh9 = value as u8;
                value >>= 8 as libc::c_int;
                bits = (bits as libc::c_uint).wrapping_sub(8 as libc::c_int as libc::c_uint) as u32
                    as u32;
                if !(bits < 8 as libc::c_int as libc::c_uint) {
                    continue;
                }
                if value != 0 {
                    current_block = 17909480686762627388;
                    break 's_3;
                }
                bits = 0 as libc::c_int as u32;
                break;
            }
            if bits != 0 {
                current_block = 17909480686762627388;
                break;
            }
        }
    }
    match current_block {
        15904375183555213903 => {
            if srclen == 0 && dstpos <= *dstlen {
                *dstlen = dstpos;
                return src;
            }
        }
        _ => {}
    }
    *dstlen = 0 as libc::c_int as size_t;
    return 0 as *const u8;
}

pub(crate) unsafe fn decode64_uint32(
    mut dst: *mut u32,
    mut src: *const u8,
    mut min: u32,
) -> *const u8 {
    let mut current_block: u64;
    let mut start: u32 = 0 as libc::c_int as u32;
    let mut end: u32 = 47 as libc::c_int as u32;
    let mut chars: u32 = 1 as libc::c_int as u32;
    let mut bits: u32 = 0 as libc::c_int as u32;
    let mut c: u32 = 0;
    let fresh2 = src;
    src = src.offset(1);
    c = atoi64(*fresh2);
    if !(c > 63 as libc::c_int as libc::c_uint) {
        *dst = min;
        while c > end {
            *dst = (*dst as libc::c_uint).wrapping_add(
                end.wrapping_add(1 as libc::c_int as libc::c_uint)
                    .wrapping_sub(start)
                    << bits,
            ) as u32 as u32;
            start = end.wrapping_add(1 as libc::c_int as libc::c_uint);
            end = start.wrapping_add(
                (62 as libc::c_int as libc::c_uint)
                    .wrapping_sub(end)
                    .wrapping_div(2 as libc::c_int as libc::c_uint),
            );
            chars = chars.wrapping_add(1);
            chars;
            bits =
                (bits as libc::c_uint).wrapping_add(6 as libc::c_int as libc::c_uint) as u32 as u32;
        }
        *dst = (*dst as libc::c_uint).wrapping_add(c.wrapping_sub(start) << bits) as u32 as u32;
        loop {
            chars = chars.wrapping_sub(1);
            if !(chars != 0) {
                current_block = 2979737022853876585;
                break;
            }
            let fresh3 = src;
            src = src.offset(1);
            c = atoi64(*fresh3);
            if c > 63 as libc::c_int as libc::c_uint {
                current_block = 18054886181315620467;
                break;
            }
            bits =
                (bits as libc::c_uint).wrapping_sub(6 as libc::c_int as libc::c_uint) as u32 as u32;
            *dst = (*dst as libc::c_uint).wrapping_add(c << bits) as u32 as u32;
        }
        match current_block {
            18054886181315620467 => {}
            _ => return src,
        }
    }
    *dst = 0 as libc::c_int as u32;
    return 0 as *const u8;
}

pub(crate) unsafe fn decode64_uint32_fixed(
    mut dst: *mut u32,
    mut dstbits: u32,
    mut src: *const u8,
) -> *const u8 {
    let mut bits: u32 = 0;
    *dst = 0 as libc::c_int as u32;
    bits = 0 as libc::c_int as u32;
    while bits < dstbits {
        let fresh6 = src;
        src = src.offset(1);
        let mut c: u32 = atoi64(*fresh6);
        if c > 63 as libc::c_int as libc::c_uint {
            *dst = 0 as libc::c_int as u32;
            return 0 as *const u8;
        }
        *dst |= c << bits;
        bits = (bits as libc::c_uint).wrapping_add(6 as libc::c_int as libc::c_uint) as u32 as u32;
    }
    return src;
}

pub(crate) unsafe fn encode64(
    mut dst: *mut u8,
    mut dstlen: size_t,
    mut src: *const u8,
    mut srclen: size_t,
) -> *mut u8 {
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < srclen {
        let mut dnext: *mut u8 = 0 as *mut u8;
        let mut value: u32 = 0 as libc::c_int as u32;
        let mut bits: u32 = 0 as libc::c_int as u32;
        loop {
            let fresh5 = i;
            i = i.wrapping_add(1);
            value |= (*src.offset(fresh5 as isize) as u32) << bits;
            bits = (bits as libc::c_uint).wrapping_add(8);
            if !(bits < 24 as libc::c_int as libc::c_uint && i < srclen) {
                break;
            }
        }
        dnext = encode64_uint32_fixed(dst, dstlen, value, bits);
        if dnext.is_null() {
            return 0 as *mut u8;
        }
        dstlen = dstlen.wrapping_sub(dnext.offset_from(dst) as u64);
        dst = dnext;
    }
    if dstlen < 1 as libc::c_int as libc::c_ulong {
        return 0 as *mut u8;
    }
    *dst = 0 as libc::c_int as u8;
    return dst;
}

pub(crate) unsafe fn encode64_uint32(
    mut dst: *mut u8,
    mut dstlen: size_t,
    mut src: u32,
    mut min: u32,
) -> *mut u8 {
    let mut start: u32 = 0 as libc::c_int as u32;
    let mut end: u32 = 47 as libc::c_int as u32;
    let mut chars: u32 = 1 as libc::c_int as u32;
    let mut bits: u32 = 0 as libc::c_int as u32;
    if src < min {
        return 0 as *mut u8;
    }
    src = (src as libc::c_uint).wrapping_sub(min) as u32 as u32;
    loop {
        let mut count: u32 = end
            .wrapping_add(1 as libc::c_int as libc::c_uint)
            .wrapping_sub(start)
            << bits;
        if src < count {
            break;
        }
        if start >= 63 as libc::c_int as libc::c_uint {
            return 0 as *mut u8;
        }
        start = end.wrapping_add(1 as libc::c_int as libc::c_uint);
        end = start.wrapping_add(
            (62 as libc::c_int as libc::c_uint)
                .wrapping_sub(end)
                .wrapping_div(2 as libc::c_int as libc::c_uint),
        );
        src = (src as libc::c_uint).wrapping_sub(count) as u32 as u32;
        chars = chars.wrapping_add(1);
        chars;
        bits = (bits as libc::c_uint).wrapping_add(6 as libc::c_int as libc::c_uint) as u32 as u32;
    }
    if dstlen <= chars as libc::c_ulong {
        return 0 as *mut u8;
    }
    let fresh0 = dst;
    dst = dst.offset(1);
    *fresh0 = itoa64[(start + (src >> bits)) as usize];
    loop {
        chars = chars.wrapping_sub(1);
        if !(chars != 0) {
            break;
        }
        bits = (bits as libc::c_uint).wrapping_sub(6 as libc::c_int as libc::c_uint) as u32 as u32;
        let fresh1 = dst;
        dst = dst.offset(1);
        *fresh1 = itoa64[(src >> bits & 0x3f) as usize];
    }
    *dst = 0 as libc::c_int as u8;
    return dst;
}

unsafe fn encode64_uint32_fixed(
    mut dst: *mut u8,
    mut dstlen: size_t,
    mut src: u32,
    mut srcbits: u32,
) -> *mut u8 {
    let mut bits: u32 = 0;
    bits = 0 as libc::c_int as u32;
    while bits < srcbits {
        if dstlen < 2 as libc::c_int as libc::c_ulong {
            return 0 as *mut u8;
        }
        let fresh4 = dst;
        dst = dst.offset(1);
        *fresh4 = itoa64[(src & 0x3f) as usize];
        dstlen = dstlen.wrapping_sub(1);
        dstlen;
        src >>= 6 as libc::c_int;
        bits = (bits as libc::c_uint).wrapping_add(6 as libc::c_int as libc::c_uint) as u32 as u32;
    }
    if src != 0 || dstlen < 1 as libc::c_int as libc::c_ulong {
        return 0 as *mut u8;
    }
    *dst = 0 as libc::c_int as u8;
    return dst;
}

pub(crate) unsafe fn encrypt(
    mut data: *mut libc::c_uchar,
    mut datalen: size_t,
    mut key: *const Binary,
    mut dir: encrypt_dir_t,
) {
    let mut ctx: SHA256_CTX = SHA256_CTX {
        state: [0; 8],
        count: 0,
        buf: [0; 64],
    };
    let mut f: [libc::c_uchar; 36] = [0; 36];
    let mut halflen: size_t = 0;
    let mut which: size_t = 0;
    let mut mask: libc::c_uchar = 0;
    let mut round: libc::c_uchar = 0;
    let mut target: libc::c_uchar = 0;
    if datalen == 0 {
        return;
    }
    if datalen > 64 as libc::c_int as libc::c_ulong {
        datalen = 64 as libc::c_int as size_t;
    }
    halflen = datalen >> 1 as libc::c_int;
    which = 0 as libc::c_int as size_t;
    mask = 0xf as libc::c_int as libc::c_uchar;
    round = 0 as libc::c_int as libc::c_uchar;
    target = 5 as libc::c_int as libc::c_uchar;
    if dir as libc::c_int == DEC as libc::c_int {
        which = halflen;
        mask = (mask as libc::c_int ^ 0xff as libc::c_int) as libc::c_uchar;
        round = target;
        target = 0 as libc::c_int as libc::c_uchar;
    }
    f[32 as libc::c_int as usize] = 0 as libc::c_int as libc::c_uchar;
    f[33 as libc::c_int as usize] =
        ::core::mem::size_of::<Binary>() as libc::c_ulong as libc::c_uchar;
    f[34 as libc::c_int as usize] = datalen as libc::c_uchar;
    loop {
        SHA256_Init(&mut ctx);
        f[35 as libc::c_int as usize] = round;
        SHA256_Update(
            &mut ctx,
            &mut *f.as_mut_ptr().offset(32 as libc::c_int as isize) as *mut libc::c_uchar
                as *const libc::c_void,
            4 as libc::c_int as size_t,
        );
        SHA256_Update(
            &mut ctx,
            key as *const libc::c_void,
            ::core::mem::size_of::<Binary>() as libc::c_ulong,
        );
        SHA256_Update(
            &mut ctx,
            &mut *data.offset(which as isize) as *mut libc::c_uchar as *const libc::c_void,
            halflen,
        );
        if datalen & 1 as libc::c_int as libc::c_ulong != 0 {
            f[0 as libc::c_int as usize] = (*data
                .offset(datalen.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize)
                as libc::c_int
                & mask as libc::c_int) as libc::c_uchar;
            SHA256_Update(
                &mut ctx,
                f.as_mut_ptr() as *const libc::c_void,
                1 as libc::c_int as size_t,
            );
        }
        SHA256_Final(f.as_mut_ptr(), &mut ctx);
        which ^= halflen;
        memxor(&mut *data.offset(which as isize), f.as_mut_ptr(), halflen);
        if datalen & 1 as libc::c_int as libc::c_ulong != 0 {
            mask = (mask as libc::c_int ^ 0xff as libc::c_int) as libc::c_uchar;
            let ref mut fresh13 =
                *data.offset(datalen.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize);
            *fresh13 = (*fresh13 as libc::c_int
                ^ f[halflen as usize] as libc::c_int & mask as libc::c_int)
                as libc::c_uchar;
        }
        if round as libc::c_int == target as libc::c_int {
            break;
        }
        round = (round as libc::c_int + dir as libc::c_int) as libc::c_uchar;
    }
}

pub(crate) unsafe fn integerify(mut B: *const u32, mut r: size_t) -> u64 {
    let mut X: *const u32 = &*B.offset(
        (2 as libc::c_int as libc::c_ulong)
            .wrapping_mul(r)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_mul(16 as libc::c_int as libc::c_ulong) as isize,
    ) as *const u32;
    return ((*X.offset(13 as libc::c_int as isize) as u64) << 32 as libc::c_int)
        .wrapping_add(*X.offset(0 as libc::c_int as isize) as libc::c_ulong);
}

#[inline]
pub(crate) unsafe fn le32dec(mut pp: *const libc::c_void) -> u32 {
    let mut p: *const u8 = pp as *const u8;
    return (*p.offset(0 as libc::c_int as isize) as u32)
        .wrapping_add((*p.offset(1 as libc::c_int as isize) as u32) << 8 as libc::c_int)
        .wrapping_add((*p.offset(2 as libc::c_int as isize) as u32) << 16 as libc::c_int)
        .wrapping_add((*p.offset(3 as libc::c_int as isize) as u32) << 24 as libc::c_int);
}

#[inline]
pub(crate) unsafe fn le32enc(mut pp: *mut libc::c_void, mut x: u32) {
    let mut p: *mut u8 = pp as *mut u8;
    *p.offset(0 as libc::c_int as isize) = (x & 0xff as libc::c_int as libc::c_uint) as u8;
    *p.offset(1 as libc::c_int as isize) =
        (x >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u8;
    *p.offset(2 as libc::c_int as isize) =
        (x >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u8;
    *p.offset(3 as libc::c_int as isize) =
        (x >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u8;
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

pub(crate) unsafe fn N2log2(mut N: u64) -> u32 {
    let mut N_log2: u32 = 0;
    if N < 2 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int as u32;
    }
    N_log2 = 2 as libc::c_int as u32;
    while N >> N_log2 != 0 as libc::c_int as libc::c_ulong {
        N_log2 = N_log2.wrapping_add(1);
        N_log2;
    }
    N_log2 = N_log2.wrapping_sub(1);
    N_log2;
    if N >> N_log2 != 1 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int as u32;
    }
    return N_log2;
}

pub(crate) unsafe fn p2floor(mut x: u64) -> u64 {
    let mut y: u64 = 0;
    loop {
        y = x & x.wrapping_sub(1 as libc::c_int as libc::c_ulong);
        if !(y != 0) {
            break;
        }
        x = y;
    }
    return x;
}

pub(crate) unsafe fn wrap(mut x: u64, mut i: u64) -> u64 {
    let mut n: u64 = p2floor(i);
    return (x & n.wrapping_sub(1 as libc::c_int as libc::c_ulong)).wrapping_add(i.wrapping_sub(n));
}
