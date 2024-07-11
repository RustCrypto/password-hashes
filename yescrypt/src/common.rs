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
    sha256::libcperciva_SHA256_CTX, size_t, uint32_t, uint64_t, uint8_t, yescrypt_binary_t,
    yescrypt_flags_t, yescrypt_local_t, yescrypt_params_t, yescrypt_shared_t,
};

extern "C" {
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    fn strrchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn libcperciva_SHA256_Init(_: *mut libcperciva_SHA256_CTX);
    fn libcperciva_SHA256_Update(_: *mut libcperciva_SHA256_CTX, _: *const libc::c_void, _: size_t);
    fn libcperciva_SHA256_Final(_: *mut uint8_t, _: *mut libcperciva_SHA256_CTX);
    fn yescrypt_free_local(local: *mut yescrypt_local_t) -> libc::c_int;
    fn yescrypt_kdf(
        shared: *const yescrypt_shared_t,
        local: *mut yescrypt_local_t,
        passwd: *const uint8_t,
        passwdlen: size_t,
        salt: *const uint8_t,
        saltlen: size_t,
        params: *const yescrypt_params_t,
        buf: *mut uint8_t,
        buflen: size_t,
    ) -> libc::c_int;
    fn yescrypt_init_local(local: *mut yescrypt_local_t) -> libc::c_int;
}

pub type encrypt_dir_t = libc::c_int;

pub const DEC: encrypt_dir_t = -1;
pub const ENC: encrypt_dir_t = 1;
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

unsafe extern "C" fn encode64_uint32(
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
    if dstlen <= chars as libc::c_ulong {
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

#[inline]
unsafe extern "C" fn atoi64(mut src: uint8_t) -> uint32_t {
    if src as libc::c_int >= '.' as i32 && src as libc::c_int <= 'z' as i32 {
        return atoi64_partial[(src as libc::c_int - '.' as i32) as usize] as uint32_t;
    }
    return 64 as libc::c_int as uint32_t;
}

unsafe extern "C" fn decode64_uint32(
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

unsafe extern "C" fn encode64_uint32_fixed(
    mut dst: *mut uint8_t,
    mut dstlen: size_t,
    mut src: uint32_t,
    mut srcbits: uint32_t,
) -> *mut uint8_t {
    let mut bits: uint32_t = 0;
    bits = 0 as libc::c_int as uint32_t;
    while bits < srcbits {
        if dstlen < 2 as libc::c_int as libc::c_ulong {
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
    if src != 0 || dstlen < 1 as libc::c_int as libc::c_ulong {
        return 0 as *mut uint8_t;
    }
    *dst = 0 as libc::c_int as uint8_t;
    return dst;
}

unsafe extern "C" fn encode64(
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
            bits = (bits as libc::c_uint).wrapping_add(8 as libc::c_int as libc::c_uint) as uint32_t
                as uint32_t;
            if !(bits < 24 as libc::c_int as libc::c_uint && i < srclen) {
                break;
            }
        }
        dnext = encode64_uint32_fixed(dst, dstlen, value, bits);
        if dnext.is_null() {
            return 0 as *mut uint8_t;
        }
        dstlen = (dstlen as libc::c_ulong)
            .wrapping_sub(dnext.offset_from(dst) as libc::c_long as libc::c_ulong)
            as size_t as size_t;
        dst = dnext;
    }
    if dstlen < 1 as libc::c_int as libc::c_ulong {
        return 0 as *mut uint8_t;
    }
    *dst = 0 as libc::c_int as uint8_t;
    return dst;
}

unsafe extern "C" fn decode64_uint32_fixed(
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

unsafe extern "C" fn decode64(
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

unsafe extern "C" fn memxor(
    mut dst: *mut libc::c_uchar,
    mut src: *mut libc::c_uchar,
    mut size: size_t,
) {
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

unsafe extern "C" fn encrypt(
    mut data: *mut libc::c_uchar,
    mut datalen: size_t,
    mut key: *const yescrypt_binary_t,
    mut dir: encrypt_dir_t,
) {
    let mut ctx: libcperciva_SHA256_CTX = libcperciva_SHA256_CTX {
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
        ::core::mem::size_of::<yescrypt_binary_t>() as libc::c_ulong as libc::c_uchar;
    f[34 as libc::c_int as usize] = datalen as libc::c_uchar;
    loop {
        libcperciva_SHA256_Init(&mut ctx);
        f[35 as libc::c_int as usize] = round;
        libcperciva_SHA256_Update(
            &mut ctx,
            &mut *f.as_mut_ptr().offset(32 as libc::c_int as isize) as *mut libc::c_uchar
                as *const libc::c_void,
            4 as libc::c_int as size_t,
        );
        libcperciva_SHA256_Update(
            &mut ctx,
            key as *const libc::c_void,
            ::core::mem::size_of::<yescrypt_binary_t>() as libc::c_ulong,
        );
        libcperciva_SHA256_Update(
            &mut ctx,
            &mut *data.offset(which as isize) as *mut libc::c_uchar as *const libc::c_void,
            halflen,
        );
        if datalen & 1 as libc::c_int as libc::c_ulong != 0 {
            f[0 as libc::c_int as usize] = (*data
                .offset(datalen.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize)
                as libc::c_int
                & mask as libc::c_int) as libc::c_uchar;
            libcperciva_SHA256_Update(
                &mut ctx,
                f.as_mut_ptr() as *const libc::c_void,
                1 as libc::c_int as size_t,
            );
        }
        libcperciva_SHA256_Final(f.as_mut_ptr(), &mut ctx);
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

#[no_mangle]
pub unsafe extern "C" fn yescrypt_r(
    mut shared: *const yescrypt_shared_t,
    mut local: *mut yescrypt_local_t,
    mut passwd: *const uint8_t,
    mut passwdlen: size_t,
    mut setting: *const uint8_t,
    mut key: *const yescrypt_binary_t,
    mut buf: *mut uint8_t,
    mut buflen: size_t,
) -> *mut uint8_t {
    let mut current_block: u64;
    let mut saltbin: [libc::c_uchar; 64] = [0; 64];
    let mut hashbin: [libc::c_uchar; 32] = [0; 32];
    let mut src: *const uint8_t = 0 as *const uint8_t;
    let mut saltstr: *const uint8_t = 0 as *const uint8_t;
    let mut salt: *const uint8_t = 0 as *const uint8_t;
    let mut dst: *mut uint8_t = 0 as *mut uint8_t;
    let mut need: size_t = 0;
    let mut prefixlen: size_t = 0;
    let mut saltstrlen: size_t = 0;
    let mut saltlen: size_t = 0;
    let mut params: yescrypt_params_t = {
        let mut init = yescrypt_params_t {
            flags: 0,
            N: 0,
            r: 0,
            p: 1 as libc::c_int as uint32_t,
            t: 0,
            g: 0,
            NROM: 0,
        };
        init
    };
    if *setting.offset(0 as libc::c_int as isize) as libc::c_int != '$' as i32
        || *setting.offset(1 as libc::c_int as isize) as libc::c_int != '7' as i32
            && *setting.offset(1 as libc::c_int as isize) as libc::c_int != 'y' as i32
        || *setting.offset(2 as libc::c_int as isize) as libc::c_int != '$' as i32
    {
        return 0 as *mut uint8_t;
    }
    src = setting.offset(3 as libc::c_int as isize);
    if *setting.offset(1 as libc::c_int as isize) as libc::c_int == '7' as i32 {
        let fresh14 = src;
        src = src.offset(1);
        let mut N_log2: uint32_t = atoi64(*fresh14);
        if N_log2 < 1 as libc::c_int as libc::c_uint || N_log2 > 63 as libc::c_int as libc::c_uint {
            return 0 as *mut uint8_t;
        }
        params.N = (1 as libc::c_int as uint64_t) << N_log2;
        src = decode64_uint32_fixed(&mut params.r, 30 as libc::c_int as uint32_t, src);
        if src.is_null() {
            return 0 as *mut uint8_t;
        }
        src = decode64_uint32_fixed(&mut params.p, 30 as libc::c_int as uint32_t, src);
        if src.is_null() {
            return 0 as *mut uint8_t;
        }
        if !key.is_null() {
            return 0 as *mut uint8_t;
        }
    } else {
        let mut flavor: uint32_t = 0;
        let mut N_log2_0: uint32_t = 0;
        src = decode64_uint32(&mut flavor, src, 0 as libc::c_int as uint32_t);
        if src.is_null() {
            return 0 as *mut uint8_t;
        }
        if flavor < 0x2 as libc::c_int as libc::c_uint {
            params.flags = flavor;
        } else if flavor
            <= (0x2 as libc::c_int + (0x3fc as libc::c_int >> 2 as libc::c_int)) as libc::c_uint
        {
            params.flags = (0x2 as libc::c_int as libc::c_uint).wrapping_add(
                flavor.wrapping_sub(0x2 as libc::c_int as libc::c_uint) << 2 as libc::c_int,
            );
        } else {
            return 0 as *mut uint8_t;
        }
        src = decode64_uint32(&mut N_log2_0, src, 1 as libc::c_int as uint32_t);
        if src.is_null() || N_log2_0 > 63 as libc::c_int as libc::c_uint {
            return 0 as *mut uint8_t;
        }
        params.N = (1 as libc::c_int as uint64_t) << N_log2_0;
        src = decode64_uint32(&mut params.r, src, 1 as libc::c_int as uint32_t);
        if src.is_null() {
            return 0 as *mut uint8_t;
        }
        if *src as libc::c_int != '$' as i32 {
            let mut have: uint32_t = 0;
            src = decode64_uint32(&mut have, src, 1 as libc::c_int as uint32_t);
            if src.is_null() {
                return 0 as *mut uint8_t;
            }
            if have & 1 as libc::c_int as libc::c_uint != 0 {
                src = decode64_uint32(&mut params.p, src, 2 as libc::c_int as uint32_t);
                if src.is_null() {
                    return 0 as *mut uint8_t;
                }
            }
            if have & 2 as libc::c_int as libc::c_uint != 0 {
                src = decode64_uint32(&mut params.t, src, 1 as libc::c_int as uint32_t);
                if src.is_null() {
                    return 0 as *mut uint8_t;
                }
            }
            if have & 4 as libc::c_int as libc::c_uint != 0 {
                src = decode64_uint32(&mut params.g, src, 1 as libc::c_int as uint32_t);
                if src.is_null() {
                    return 0 as *mut uint8_t;
                }
            }
            if have & 8 as libc::c_int as libc::c_uint != 0 {
                let mut NROM_log2: uint32_t = 0;
                src = decode64_uint32(&mut NROM_log2, src, 1 as libc::c_int as uint32_t);
                if src.is_null() || NROM_log2 > 63 as libc::c_int as libc::c_uint {
                    return 0 as *mut uint8_t;
                }
                params.NROM = (1 as libc::c_int as uint64_t) << NROM_log2;
            }
        }
        let fresh15 = src;
        src = src.offset(1);
        if *fresh15 as libc::c_int != '$' as i32 {
            return 0 as *mut uint8_t;
        }
    }
    prefixlen = src.offset_from(setting) as libc::c_long as size_t;
    saltstr = src;
    src = strrchr(saltstr as *mut libc::c_char, '$' as i32) as *mut uint8_t;
    if !src.is_null() {
        saltstrlen = src.offset_from(saltstr) as libc::c_long as size_t;
    } else {
        saltstrlen = strlen(saltstr as *mut libc::c_char);
    }
    if *setting.offset(1 as libc::c_int as isize) as libc::c_int == '7' as i32 {
        salt = saltstr;
        saltlen = saltstrlen;
        current_block = 1623252117315916725;
    } else {
        let mut saltend: *const uint8_t = 0 as *const uint8_t;
        saltlen = ::core::mem::size_of::<[libc::c_uchar; 64]>() as libc::c_ulong;
        saltend = decode64(saltbin.as_mut_ptr(), &mut saltlen, saltstr, saltstrlen);
        if saltend.is_null() || saltend.offset_from(saltstr) as libc::c_long as size_t != saltstrlen
        {
            current_block = 3736434875406665187;
        } else {
            salt = saltbin.as_mut_ptr();
            if !key.is_null() {
                encrypt(saltbin.as_mut_ptr(), saltlen, key, ENC);
            }
            current_block = 1623252117315916725;
        }
    }
    match current_block {
        1623252117315916725 => {
            need = prefixlen
                .wrapping_add(saltstrlen)
                .wrapping_add(1 as libc::c_int as libc::c_ulong)
                .wrapping_add(
                    (::core::mem::size_of::<yescrypt_binary_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                        .wrapping_add(5 as libc::c_int as libc::c_ulong)
                        .wrapping_div(6 as libc::c_int as libc::c_ulong),
                )
                .wrapping_add(1 as libc::c_int as libc::c_ulong);
            if !(need > buflen || need < saltstrlen) {
                if !(yescrypt_kdf(
                    shared,
                    local,
                    passwd,
                    passwdlen,
                    salt,
                    saltlen,
                    &mut params,
                    hashbin.as_mut_ptr(),
                    ::core::mem::size_of::<[libc::c_uchar; 32]>() as libc::c_ulong,
                ) != 0)
                {
                    if !key.is_null() {
                        encrypt(
                            hashbin.as_mut_ptr(),
                            ::core::mem::size_of::<[libc::c_uchar; 32]>() as libc::c_ulong,
                            key,
                            ENC,
                        );
                    }
                    dst = buf;
                    memcpy(
                        dst as *mut libc::c_void,
                        setting as *const libc::c_void,
                        prefixlen.wrapping_add(saltstrlen),
                    );
                    dst = dst.offset(prefixlen.wrapping_add(saltstrlen) as isize);
                    let fresh16 = dst;
                    dst = dst.offset(1);
                    *fresh16 = '$' as i32 as uint8_t;
                    dst = encode64(
                        dst,
                        buflen.wrapping_sub(dst.offset_from(buf) as libc::c_long as libc::c_ulong),
                        hashbin.as_mut_ptr(),
                        ::core::mem::size_of::<[libc::c_uchar; 32]>() as libc::c_ulong,
                    );
                    if dst.is_null() || dst >= buf.offset(buflen as isize) {
                        return 0 as *mut uint8_t;
                    }
                    *dst = 0 as libc::c_int as uint8_t;
                    return buf;
                }
            }
        }
        _ => {}
    }
    return 0 as *mut uint8_t;
}

#[no_mangle]
pub unsafe extern "C" fn yescrypt(
    mut passwd: *const uint8_t,
    mut setting: *const uint8_t,
) -> *mut uint8_t {
    static mut buf: [uint8_t; 140] = [0; 140];
    let mut local: yescrypt_local_t = yescrypt_local_t {
        base: 0 as *mut libc::c_void,
        aligned: 0 as *mut libc::c_void,
        base_size: 0,
        aligned_size: 0,
    };
    let mut retval: *mut uint8_t = 0 as *mut uint8_t;
    if yescrypt_init_local(&mut local) != 0 {
        return 0 as *mut uint8_t;
    }
    retval = yescrypt_r(
        0 as *const yescrypt_shared_t,
        &mut local,
        passwd,
        strlen(passwd as *mut libc::c_char),
        setting,
        0 as *const yescrypt_binary_t,
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 140]>() as libc::c_ulong,
    );
    if yescrypt_free_local(&mut local) != 0 {
        return 0 as *mut uint8_t;
    }
    return retval;
}

#[no_mangle]
pub unsafe extern "C" fn yescrypt_reencrypt(
    mut hash: *mut uint8_t,
    mut from_key: *const yescrypt_binary_t,
    mut to_key: *const yescrypt_binary_t,
) -> *mut uint8_t {
    let mut current_block: u64;
    let mut retval: *mut uint8_t = 0 as *mut uint8_t;
    let mut saltstart: *mut uint8_t = 0 as *mut uint8_t;
    let mut hashstart: *mut uint8_t = 0 as *mut uint8_t;
    let mut hashend: *const uint8_t = 0 as *const uint8_t;
    let mut saltbin: [libc::c_uchar; 64] = [0; 64];
    let mut hashbin: [libc::c_uchar; 32] = [0; 32];
    let mut saltstrlen: size_t = 0;
    let mut saltlen: size_t = 0 as libc::c_int as size_t;
    let mut hashlen: size_t = 0;
    if strncmp(
        hash as *mut libc::c_char,
        b"$y$\0" as *const u8 as *const libc::c_char,
        3 as libc::c_int as libc::c_ulong,
    ) != 0
    {
        return 0 as *mut uint8_t;
    }
    saltstart = 0 as *mut uint8_t;
    hashstart = strrchr(hash as *mut libc::c_char, '$' as i32) as *mut uint8_t;
    if !hashstart.is_null() {
        if hashstart > hash {
            saltstart = hashstart.offset(-(1 as libc::c_int as isize));
            while *saltstart as libc::c_int != '$' as i32 && saltstart > hash {
                saltstart = saltstart.offset(-1);
                saltstart;
            }
            if *saltstart as libc::c_int == '$' as i32 {
                saltstart = saltstart.offset(1);
                saltstart;
            }
        }
        hashstart = hashstart.offset(1);
        hashstart;
    } else {
        hashstart = hash;
    }
    saltstrlen = (if !saltstart.is_null() {
        hashstart
            .offset(-(1 as libc::c_int as isize))
            .offset_from(saltstart) as libc::c_long
    } else {
        0 as libc::c_int as libc::c_long
    }) as size_t;
    if saltstrlen
        > ((64 as libc::c_int * 8 as libc::c_int + 5 as libc::c_int) / 6 as libc::c_int)
            as libc::c_ulong
        || strlen(hashstart as *mut libc::c_char)
            != (::core::mem::size_of::<yescrypt_binary_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                .wrapping_add(5 as libc::c_int as libc::c_ulong)
                .wrapping_div(6 as libc::c_int as libc::c_ulong)
    {
        return 0 as *mut uint8_t;
    }
    if saltstrlen != 0 {
        let mut saltend: *const uint8_t = 0 as *const uint8_t;
        saltlen = ::core::mem::size_of::<[libc::c_uchar; 64]>() as libc::c_ulong;
        saltend = decode64(saltbin.as_mut_ptr(), &mut saltlen, saltstart, saltstrlen);
        if saltend.is_null()
            || *saltend as libc::c_int != '$' as i32
            || saltlen < 1 as libc::c_int as libc::c_ulong
            || saltlen > 64 as libc::c_int as libc::c_ulong
        {
            current_block = 11385396242402735691;
        } else {
            if !from_key.is_null() {
                encrypt(saltbin.as_mut_ptr(), saltlen, from_key, ENC);
            }
            if !to_key.is_null() {
                encrypt(saltbin.as_mut_ptr(), saltlen, to_key, DEC);
            }
            current_block = 14401909646449704462;
        }
    } else {
        current_block = 14401909646449704462;
    }
    match current_block {
        14401909646449704462 => {
            hashlen = ::core::mem::size_of::<[libc::c_uchar; 32]>() as libc::c_ulong;
            hashend = decode64(
                hashbin.as_mut_ptr(),
                &mut hashlen,
                hashstart,
                (::core::mem::size_of::<yescrypt_binary_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                    .wrapping_add(5 as libc::c_int as libc::c_ulong)
                    .wrapping_div(6 as libc::c_int as libc::c_ulong),
            );
            if !(hashend.is_null()
                || *hashend as libc::c_int != 0
                || hashlen != ::core::mem::size_of::<[libc::c_uchar; 32]>() as libc::c_ulong)
            {
                if !from_key.is_null() {
                    encrypt(hashbin.as_mut_ptr(), hashlen, from_key, DEC);
                }
                if !to_key.is_null() {
                    encrypt(hashbin.as_mut_ptr(), hashlen, to_key, ENC);
                }
                if saltstrlen != 0 {
                    if (encode64(
                        saltstart,
                        saltstrlen.wrapping_add(1 as libc::c_int as libc::c_ulong),
                        saltbin.as_mut_ptr(),
                        saltlen,
                    ))
                    .is_null()
                    {
                        current_block = 11385396242402735691;
                    } else {
                        *saltstart.offset(saltstrlen as isize) = '$' as i32 as uint8_t;
                        current_block = 17281240262373992796;
                    }
                } else {
                    current_block = 17281240262373992796;
                }
                match current_block {
                    11385396242402735691 => {}
                    _ => {
                        if !(encode64(
                            hashstart,
                            (::core::mem::size_of::<yescrypt_binary_t>() as libc::c_ulong)
                                .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                                .wrapping_add(5 as libc::c_int as libc::c_ulong)
                                .wrapping_div(6 as libc::c_int as libc::c_ulong)
                                .wrapping_add(1 as libc::c_int as libc::c_ulong),
                            hashbin.as_mut_ptr(),
                            hashlen,
                        ))
                        .is_null()
                        {
                            retval = hash;
                        }
                    }
                }
            }
        }
        _ => {}
    }
    return retval;
}

unsafe extern "C" fn N2log2(mut N: uint64_t) -> uint32_t {
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

#[no_mangle]
pub unsafe extern "C" fn yescrypt_encode_params_r(
    mut params: *const yescrypt_params_t,
    mut src: *const uint8_t,
    mut srclen: size_t,
    mut buf: *mut uint8_t,
    mut buflen: size_t,
) -> *mut uint8_t {
    let mut flavor: uint32_t = 0;
    let mut N_log2: uint32_t = 0;
    let mut NROM_log2: uint32_t = 0;
    let mut have: uint32_t = 0;
    let mut dst: *mut uint8_t = 0 as *mut uint8_t;
    if srclen
        > (18446744073709551615 as libc::c_ulong).wrapping_div(16 as libc::c_int as libc::c_ulong)
    {
        return 0 as *mut uint8_t;
    }
    if (*params).flags < 0x2 as libc::c_int as libc::c_uint {
        flavor = (*params).flags;
    } else if (*params).flags & 0x3 as libc::c_int as libc::c_uint
        == 0x2 as libc::c_int as libc::c_uint
        && (*params).flags <= (0x2 as libc::c_int | 0x3fc as libc::c_int) as libc::c_uint
    {
        flavor =
            (0x2 as libc::c_int as libc::c_uint).wrapping_add((*params).flags >> 2 as libc::c_int);
    } else {
        return 0 as *mut uint8_t;
    }
    N_log2 = N2log2((*params).N);
    if N_log2 == 0 {
        return 0 as *mut uint8_t;
    }
    NROM_log2 = N2log2((*params).NROM);
    if (*params).NROM != 0 && NROM_log2 == 0 {
        return 0 as *mut uint8_t;
    }
    if ((*params).r as uint64_t).wrapping_mul((*params).p as uint64_t)
        >= ((1 as libc::c_uint) << 30 as libc::c_int) as libc::c_ulong
    {
        return 0 as *mut uint8_t;
    }
    dst = buf;
    let fresh17 = dst;
    dst = dst.offset(1);
    *fresh17 = '$' as i32 as uint8_t;
    let fresh18 = dst;
    dst = dst.offset(1);
    *fresh18 = 'y' as i32 as uint8_t;
    let fresh19 = dst;
    dst = dst.offset(1);
    *fresh19 = '$' as i32 as uint8_t;
    dst = encode64_uint32(
        dst,
        buflen.wrapping_sub(dst.offset_from(buf) as libc::c_long as libc::c_ulong),
        flavor,
        0 as libc::c_int as uint32_t,
    );
    if dst.is_null() {
        return 0 as *mut uint8_t;
    }
    dst = encode64_uint32(
        dst,
        buflen.wrapping_sub(dst.offset_from(buf) as libc::c_long as libc::c_ulong),
        N_log2,
        1 as libc::c_int as uint32_t,
    );
    if dst.is_null() {
        return 0 as *mut uint8_t;
    }
    dst = encode64_uint32(
        dst,
        buflen.wrapping_sub(dst.offset_from(buf) as libc::c_long as libc::c_ulong),
        (*params).r,
        1 as libc::c_int as uint32_t,
    );
    if dst.is_null() {
        return 0 as *mut uint8_t;
    }
    have = 0 as libc::c_int as uint32_t;
    if (*params).p != 1 as libc::c_int as libc::c_uint {
        have |= 1 as libc::c_int as libc::c_uint;
    }
    if (*params).t != 0 {
        have |= 2 as libc::c_int as libc::c_uint;
    }
    if (*params).g != 0 {
        have |= 4 as libc::c_int as libc::c_uint;
    }
    if NROM_log2 != 0 {
        have |= 8 as libc::c_int as libc::c_uint;
    }
    if have != 0 {
        dst = encode64_uint32(
            dst,
            buflen.wrapping_sub(dst.offset_from(buf) as libc::c_long as libc::c_ulong),
            have,
            1 as libc::c_int as uint32_t,
        );
        if dst.is_null() {
            return 0 as *mut uint8_t;
        }
    }
    if (*params).p != 1 as libc::c_int as libc::c_uint {
        dst = encode64_uint32(
            dst,
            buflen.wrapping_sub(dst.offset_from(buf) as libc::c_long as libc::c_ulong),
            (*params).p,
            2 as libc::c_int as uint32_t,
        );
        if dst.is_null() {
            return 0 as *mut uint8_t;
        }
    }
    if (*params).t != 0 {
        dst = encode64_uint32(
            dst,
            buflen.wrapping_sub(dst.offset_from(buf) as libc::c_long as libc::c_ulong),
            (*params).t,
            1 as libc::c_int as uint32_t,
        );
        if dst.is_null() {
            return 0 as *mut uint8_t;
        }
    }
    if (*params).g != 0 {
        dst = encode64_uint32(
            dst,
            buflen.wrapping_sub(dst.offset_from(buf) as libc::c_long as libc::c_ulong),
            (*params).g,
            1 as libc::c_int as uint32_t,
        );
        if dst.is_null() {
            return 0 as *mut uint8_t;
        }
    }
    if NROM_log2 != 0 {
        dst = encode64_uint32(
            dst,
            buflen.wrapping_sub(dst.offset_from(buf) as libc::c_long as libc::c_ulong),
            NROM_log2,
            1 as libc::c_int as uint32_t,
        );
        if dst.is_null() {
            return 0 as *mut uint8_t;
        }
    }
    if dst >= buf.offset(buflen as isize) {
        return 0 as *mut uint8_t;
    }
    let fresh20 = dst;
    dst = dst.offset(1);
    *fresh20 = '$' as i32 as uint8_t;
    dst = encode64(
        dst,
        buflen.wrapping_sub(dst.offset_from(buf) as libc::c_long as libc::c_ulong),
        src,
        srclen,
    );
    if dst.is_null() || dst >= buf.offset(buflen as isize) {
        return 0 as *mut uint8_t;
    }
    *dst = 0 as libc::c_int as uint8_t;
    return buf;
}

#[no_mangle]
pub unsafe extern "C" fn yescrypt_encode_params(
    mut params: *const yescrypt_params_t,
    mut src: *const uint8_t,
    mut srclen: size_t,
) -> *mut uint8_t {
    static mut buf: [uint8_t; 96] = [0; 96];
    return yescrypt_encode_params_r(
        params,
        src,
        srclen,
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 96]>() as libc::c_ulong,
    );
}

#[no_mangle]
pub unsafe extern "C" fn crypto_scrypt(
    mut passwd: *const uint8_t,
    mut passwdlen: size_t,
    mut salt: *const uint8_t,
    mut saltlen: size_t,
    mut N: uint64_t,
    mut r: uint32_t,
    mut p: uint32_t,
    mut buf: *mut uint8_t,
    mut buflen: size_t,
) -> libc::c_int {
    let mut local: yescrypt_local_t = yescrypt_local_t {
        base: 0 as *mut libc::c_void,
        aligned: 0 as *mut libc::c_void,
        base_size: 0,
        aligned_size: 0,
    };
    let mut params: yescrypt_params_t = {
        let mut init = yescrypt_params_t {
            flags: 0 as libc::c_int as yescrypt_flags_t,
            N: N,
            r: r,
            p: p,
            t: 0,
            g: 0,
            NROM: 0,
        };
        init
    };
    let mut retval: libc::c_int = 0;
    if yescrypt_init_local(&mut local) != 0 {
        return -(1 as libc::c_int);
    }
    retval = yescrypt_kdf(
        0 as *const yescrypt_shared_t,
        &mut local,
        passwd,
        passwdlen,
        salt,
        saltlen,
        &mut params,
        buf,
        buflen,
    );
    if yescrypt_free_local(&mut local) != 0 {
        return -(1 as libc::c_int);
    }
    return retval;
}
