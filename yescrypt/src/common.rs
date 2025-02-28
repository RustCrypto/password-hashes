#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]

use crate::{Binary, DEC, encrypt_dir_t, size_t, uint8_t, uint32_t, uint64_t};

static mut itoa64: *const libc::c_char =
    b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\0" as *const u8
        as *const libc::c_char;
static mut atoi64_partial: [uint8_t; 77] = [
    0 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    6 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    9 as libc::c_int as uint8_t,
    10 as libc::c_int as uint8_t,
    11 as libc::c_int as uint8_t,
    64 as libc::c_int as uint8_t,
    64 as libc::c_int as uint8_t,
    64 as libc::c_int as uint8_t,
    64 as libc::c_int as uint8_t,
    64 as libc::c_int as uint8_t,
    64 as libc::c_int as uint8_t,
    64 as libc::c_int as uint8_t,
    12 as libc::c_int as uint8_t,
    13 as libc::c_int as uint8_t,
    14 as libc::c_int as uint8_t,
    15 as libc::c_int as uint8_t,
    16 as libc::c_int as uint8_t,
    17 as libc::c_int as uint8_t,
    18 as libc::c_int as uint8_t,
    19 as libc::c_int as uint8_t,
    20 as libc::c_int as uint8_t,
    21 as libc::c_int as uint8_t,
    22 as libc::c_int as uint8_t,
    23 as libc::c_int as uint8_t,
    24 as libc::c_int as uint8_t,
    25 as libc::c_int as uint8_t,
    26 as libc::c_int as uint8_t,
    27 as libc::c_int as uint8_t,
    28 as libc::c_int as uint8_t,
    29 as libc::c_int as uint8_t,
    30 as libc::c_int as uint8_t,
    31 as libc::c_int as uint8_t,
    32 as libc::c_int as uint8_t,
    33 as libc::c_int as uint8_t,
    34 as libc::c_int as uint8_t,
    35 as libc::c_int as uint8_t,
    36 as libc::c_int as uint8_t,
    37 as libc::c_int as uint8_t,
    64 as libc::c_int as uint8_t,
    64 as libc::c_int as uint8_t,
    64 as libc::c_int as uint8_t,
    64 as libc::c_int as uint8_t,
    64 as libc::c_int as uint8_t,
    64 as libc::c_int as uint8_t,
    38 as libc::c_int as uint8_t,
    39 as libc::c_int as uint8_t,
    40 as libc::c_int as uint8_t,
    41 as libc::c_int as uint8_t,
    42 as libc::c_int as uint8_t,
    43 as libc::c_int as uint8_t,
    44 as libc::c_int as uint8_t,
    45 as libc::c_int as uint8_t,
    46 as libc::c_int as uint8_t,
    47 as libc::c_int as uint8_t,
    48 as libc::c_int as uint8_t,
    49 as libc::c_int as uint8_t,
    50 as libc::c_int as uint8_t,
    51 as libc::c_int as uint8_t,
    52 as libc::c_int as uint8_t,
    53 as libc::c_int as uint8_t,
    54 as libc::c_int as uint8_t,
    55 as libc::c_int as uint8_t,
    56 as libc::c_int as uint8_t,
    57 as libc::c_int as uint8_t,
    58 as libc::c_int as uint8_t,
    59 as libc::c_int as uint8_t,
    60 as libc::c_int as uint8_t,
    61 as libc::c_int as uint8_t,
    62 as libc::c_int as uint8_t,
    63 as libc::c_int as uint8_t,
];

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

#[inline]
pub(crate) unsafe fn atoi64(mut src: uint8_t) -> uint32_t {
    if src as libc::c_int >= '.' as i32 && src as libc::c_int <= 'z' as i32 {
        return atoi64_partial[(src as libc::c_int - '.' as i32) as usize] as uint32_t;
    }
    return 64 as libc::c_int as uint32_t;
}

pub(crate) unsafe fn decode64(
    mut dst: *mut uint8_t,
    mut dstlen: *mut size_t,
    mut src: *const uint8_t,
    mut srclen: size_t,
) -> *const uint8_t {
    let mut current_block: u64;
    let mut dstpos: size_t = 0 as libc::c_int as size_t;
    's_3: loop {
        if !(dstpos <= *dstlen && srclen != 0) {
            current_block = 15904375183555213903;
            break;
        }
        let mut value: uint32_t = 0 as libc::c_int as uint32_t;
        let mut bits: uint32_t = 0 as libc::c_int as uint32_t;
        loop {
            let fresh7 = srclen;
            srclen = srclen.wrapping_sub(1);
            if !(fresh7 != 0) {
                break;
            }
            let mut c: uint32_t = atoi64(*src);
            if c > 63 as libc::c_int as libc::c_uint {
                srclen = 0 as libc::c_int as size_t;
                break;
            } else {
                src = src.offset(1);
                src;
                value |= c << bits;
                bits = (bits as libc::c_uint).wrapping_add(6 as libc::c_int as libc::c_uint)
                    as uint32_t as uint32_t;
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
                *fresh9 = value as uint8_t;
                value >>= 8 as libc::c_int;
                bits = (bits as libc::c_uint).wrapping_sub(8 as libc::c_int as libc::c_uint)
                    as uint32_t as uint32_t;
                if !(bits < 8 as libc::c_int as libc::c_uint) {
                    continue;
                }
                if value != 0 {
                    current_block = 17909480686762627388;
                    break 's_3;
                }
                bits = 0 as libc::c_int as uint32_t;
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
    return 0 as *const uint8_t;
}

pub(crate) unsafe fn decode64_uint32(
    mut dst: *mut uint32_t,
    mut src: *const uint8_t,
    mut min: uint32_t,
) -> *const uint8_t {
    let mut current_block: u64;
    let mut start: uint32_t = 0 as libc::c_int as uint32_t;
    let mut end: uint32_t = 47 as libc::c_int as uint32_t;
    let mut chars: uint32_t = 1 as libc::c_int as uint32_t;
    let mut bits: uint32_t = 0 as libc::c_int as uint32_t;
    let mut c: uint32_t = 0;
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
            ) as uint32_t as uint32_t;
            start = end.wrapping_add(1 as libc::c_int as libc::c_uint);
            end = start.wrapping_add(
                (62 as libc::c_int as libc::c_uint)
                    .wrapping_sub(end)
                    .wrapping_div(2 as libc::c_int as libc::c_uint),
            );
            chars = chars.wrapping_add(1);
            chars;
            bits = (bits as libc::c_uint).wrapping_add(6 as libc::c_int as libc::c_uint) as uint32_t
                as uint32_t;
        }
        *dst = (*dst as libc::c_uint).wrapping_add(c.wrapping_sub(start) << bits) as uint32_t
            as uint32_t;
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
            bits = (bits as libc::c_uint).wrapping_sub(6 as libc::c_int as libc::c_uint) as uint32_t
                as uint32_t;
            *dst = (*dst as libc::c_uint).wrapping_add(c << bits) as uint32_t as uint32_t;
        }
        match current_block {
            18054886181315620467 => {}
            _ => return src,
        }
    }
    *dst = 0 as libc::c_int as uint32_t;
    return 0 as *const uint8_t;
}

pub(crate) unsafe fn decode64_uint32_fixed(
    mut dst: *mut uint32_t,
    mut dstbits: uint32_t,
    mut src: *const uint8_t,
) -> *const uint8_t {
    let mut bits: uint32_t = 0;
    *dst = 0 as libc::c_int as uint32_t;
    bits = 0 as libc::c_int as uint32_t;
    while bits < dstbits {
        let fresh6 = src;
        src = src.offset(1);
        let mut c: uint32_t = atoi64(*fresh6);
        if c > 63 as libc::c_int as libc::c_uint {
            *dst = 0 as libc::c_int as uint32_t;
            return 0 as *const uint8_t;
        }
        *dst |= c << bits;
        bits = (bits as libc::c_uint).wrapping_add(6 as libc::c_int as libc::c_uint) as uint32_t
            as uint32_t;
    }
    return src;
}

pub(crate) unsafe fn encode64(
    mut dst: *mut uint8_t,
    mut dstlen: size_t,
    mut src: *const uint8_t,
    mut srclen: size_t,
) -> *mut uint8_t {
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < srclen {
        let mut dnext: *mut uint8_t = 0 as *mut uint8_t;
        let mut value: uint32_t = 0 as libc::c_int as uint32_t;
        let mut bits: uint32_t = 0 as libc::c_int as uint32_t;
        loop {
            let fresh5 = i;
            i = i.wrapping_add(1);
            value |= (*src.offset(fresh5 as isize) as uint32_t) << bits;
            bits = (bits as libc::c_uint).wrapping_add(8);
            if !(bits < 24 as libc::c_int as libc::c_uint && i < srclen) {
                break;
            }
        }
        dnext = encode64_uint32_fixed(dst, dstlen, value, bits);
        if dnext.is_null() {
            return 0 as *mut uint8_t;
        }
        dstlen = dstlen.wrapping_sub(dnext.offset_from(dst) as usize);
        dst = dnext;
    }
    if dstlen < 1 {
        return 0 as *mut uint8_t;
    }
    *dst = 0 as libc::c_int as uint8_t;
    return dst;
}

pub(crate) unsafe fn encode64_uint32(
    mut dst: *mut uint8_t,
    mut dstlen: size_t,
    mut src: uint32_t,
    mut min: uint32_t,
) -> *mut uint8_t {
    let mut start: uint32_t = 0 as libc::c_int as uint32_t;
    let mut end: uint32_t = 47 as libc::c_int as uint32_t;
    let mut chars: uint32_t = 1 as libc::c_int as uint32_t;
    let mut bits: uint32_t = 0 as libc::c_int as uint32_t;
    if src < min {
        return 0 as *mut uint8_t;
    }
    src = (src as libc::c_uint).wrapping_sub(min) as uint32_t as uint32_t;
    loop {
        let mut count: uint32_t = end
            .wrapping_add(1 as libc::c_int as libc::c_uint)
            .wrapping_sub(start)
            << bits;
        if src < count {
            break;
        }
        if start >= 63 as libc::c_int as libc::c_uint {
            return 0 as *mut uint8_t;
        }
        start = end.wrapping_add(1 as libc::c_int as libc::c_uint);
        end = start.wrapping_add(
            (62 as libc::c_int as libc::c_uint)
                .wrapping_sub(end)
                .wrapping_div(2 as libc::c_int as libc::c_uint),
        );
        src = (src as libc::c_uint).wrapping_sub(count) as uint32_t as uint32_t;
        chars = chars.wrapping_add(1);
        chars;
        bits = (bits as libc::c_uint).wrapping_add(6 as libc::c_int as libc::c_uint) as uint32_t
            as uint32_t;
    }
    if dstlen <= chars as usize {
        return 0 as *mut uint8_t;
    }
    let fresh0 = dst;
    dst = dst.offset(1);
    *fresh0 = *itoa64.offset(start.wrapping_add(src >> bits) as isize) as uint8_t;
    loop {
        chars = chars.wrapping_sub(1);
        if !(chars != 0) {
            break;
        }
        bits = (bits as libc::c_uint).wrapping_sub(6 as libc::c_int as libc::c_uint) as uint32_t
            as uint32_t;
        let fresh1 = dst;
        dst = dst.offset(1);
        *fresh1 =
            *itoa64.offset((src >> bits & 0x3f as libc::c_int as libc::c_uint) as isize) as uint8_t;
    }
    *dst = 0 as libc::c_int as uint8_t;
    return dst;
}

unsafe fn encode64_uint32_fixed(
    mut dst: *mut uint8_t,
    mut dstlen: size_t,
    mut src: uint32_t,
    mut srcbits: uint32_t,
) -> *mut uint8_t {
    let mut bits: uint32_t = 0;
    bits = 0 as libc::c_int as uint32_t;
    while bits < srcbits {
        if dstlen < 2 {
            return 0 as *mut uint8_t;
        }
        let fresh4 = dst;
        dst = dst.offset(1);
        *fresh4 = *itoa64.offset((src & 0x3f as libc::c_int as libc::c_uint) as isize) as uint8_t;
        dstlen = dstlen.wrapping_sub(1);
        dstlen;
        src >>= 6 as libc::c_int;
        bits = (bits as libc::c_uint).wrapping_add(6 as libc::c_int as libc::c_uint) as uint32_t
            as uint32_t;
    }
    if src != 0 || dstlen < 1 {
        return 0 as *mut uint8_t;
    }
    *dst = 0 as libc::c_int as uint8_t;
    return dst;
}

pub(crate) unsafe fn encrypt(
    mut data: *mut libc::c_uchar,
    mut datalen: size_t,
    mut key: *const Binary,
    mut dir: encrypt_dir_t,
) {
    use sha2::Digest;
    use sha2::digest::array::Array;

    let mut f: [libc::c_uchar; 36] = [0; 36];
    let mut halflen: size_t = 0;
    let mut which: size_t = 0;
    let mut mask: libc::c_uchar = 0;
    let mut round: libc::c_uchar = 0;
    let mut target: libc::c_uchar = 0;
    if datalen == 0 {
        return;
    }
    if datalen > 64 {
        datalen = 64;
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
    let mut ctx2 = sha2::Sha256::new();
    loop {
        f[35 as libc::c_int as usize] = round;
        ctx2.update(&f[32..]);
        ctx2.update(&*core::ptr::slice_from_raw_parts(
            key as *const u8,
            ::core::mem::size_of::<Binary>(),
        ));
        ctx2.update(&*core::ptr::slice_from_raw_parts(
            data.offset(which as isize),
            halflen as usize,
        ));

        if datalen & 1 != 0 {
            f[0] = *data.offset(datalen.wrapping_sub(1) as isize) & mask;
            ctx2.update(&f[0..1]);
        }

        // TODO
        #[allow(deprecated)]
        ctx2.finalize_into_reset(Array::from_mut_slice(&mut f[..32]));
        which ^= halflen;
        memxor(&mut *data.offset(which as isize), f.as_mut_ptr(), halflen);
        if datalen & 1 != 0 {
            mask ^= 0xff;
            let ref mut fresh13 = *data.offset(datalen.wrapping_sub(1) as isize);
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

pub(crate) unsafe fn N2log2(mut N: uint64_t) -> uint32_t {
    let mut N_log2: uint32_t = 0;
    if N < 2 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int as uint32_t;
    }
    N_log2 = 2 as libc::c_int as uint32_t;
    while N >> N_log2 != 0 as libc::c_int as libc::c_ulong {
        N_log2 = N_log2.wrapping_add(1);
        N_log2;
    }
    N_log2 = N_log2.wrapping_sub(1);
    N_log2;
    if N >> N_log2 != 1 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int as uint32_t;
    }
    return N_log2;
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
