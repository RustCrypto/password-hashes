#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]

use crate::{size_t, uint32_t, uint64_t, uint8_t};

extern "C" {
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong) -> *mut libc::c_void;
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct libcperciva_SHA256_CTX {
    pub state: [uint32_t; 8],
    pub count: uint64_t,
    pub buf: [uint8_t; 64],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct libcperciva_HMAC_SHA256_CTX {
    pub ictx: libcperciva_SHA256_CTX,
    pub octx: libcperciva_SHA256_CTX,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub tmp8: [uint8_t; 96],
    pub state: [uint32_t; 8],
}

#[inline]
unsafe extern "C" fn libcperciva_be32dec(mut pp: *const libc::c_void) -> uint32_t {
    let mut p: *const uint8_t = pp as *const uint8_t;
    return (*p.offset(3 as libc::c_int as isize) as uint32_t)
        .wrapping_add((*p.offset(2 as libc::c_int as isize) as uint32_t) << 8 as libc::c_int)
        .wrapping_add((*p.offset(1 as libc::c_int as isize) as uint32_t) << 16 as libc::c_int)
        .wrapping_add((*p.offset(0 as libc::c_int as isize) as uint32_t) << 24 as libc::c_int);
}

#[inline]
unsafe extern "C" fn libcperciva_be32enc(mut pp: *mut libc::c_void, mut x: uint32_t) {
    let mut p: *mut uint8_t = pp as *mut uint8_t;
    *p.offset(3 as libc::c_int as isize) = (x & 0xff as libc::c_int as libc::c_uint) as uint8_t;
    *p.offset(2 as libc::c_int as isize) =
        (x >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as uint8_t;
    *p.offset(1 as libc::c_int as isize) =
        (x >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as uint8_t;
    *p.offset(0 as libc::c_int as isize) =
        (x >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as uint8_t;
}

#[inline]
unsafe extern "C" fn libcperciva_be64enc(mut pp: *mut libc::c_void, mut x: uint64_t) {
    let mut p: *mut uint8_t = pp as *mut uint8_t;
    *p.offset(7 as libc::c_int as isize) = (x & 0xff as libc::c_int as libc::c_ulong) as uint8_t;
    *p.offset(6 as libc::c_int as isize) =
        (x >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as uint8_t;
    *p.offset(5 as libc::c_int as isize) =
        (x >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as uint8_t;
    *p.offset(4 as libc::c_int as isize) =
        (x >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as uint8_t;
    *p.offset(3 as libc::c_int as isize) =
        (x >> 32 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as uint8_t;
    *p.offset(2 as libc::c_int as isize) =
        (x >> 40 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as uint8_t;
    *p.offset(1 as libc::c_int as isize) =
        (x >> 48 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as uint8_t;
    *p.offset(0 as libc::c_int as isize) =
        (x >> 56 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as uint8_t;
}

unsafe extern "C" fn be32enc_vect(
    mut dst: *mut uint8_t,
    mut src: *const uint32_t,
    mut len: size_t,
) {
    loop {
        libcperciva_be32enc(
            &mut *dst.offset(0 as libc::c_int as isize) as *mut uint8_t as *mut libc::c_void,
            *src.offset(0 as libc::c_int as isize),
        );
        libcperciva_be32enc(
            &mut *dst.offset(4 as libc::c_int as isize) as *mut uint8_t as *mut libc::c_void,
            *src.offset(1 as libc::c_int as isize),
        );
        src = src.offset(2 as libc::c_int as isize);
        dst = dst.offset(8 as libc::c_int as isize);
        len = len.wrapping_sub(1);
        if !(len != 0) {
            break;
        }
    }
}

unsafe extern "C" fn be32dec_vect(
    mut dst: *mut uint32_t,
    mut src: *const uint8_t,
    mut len: size_t,
) {
    loop {
        *dst.offset(0 as libc::c_int as isize) = libcperciva_be32dec(
            &*src.offset(0 as libc::c_int as isize) as *const uint8_t as *const libc::c_void,
        );
        *dst.offset(1 as libc::c_int as isize) = libcperciva_be32dec(
            &*src.offset(4 as libc::c_int as isize) as *const uint8_t as *const libc::c_void,
        );
        src = src.offset(8 as libc::c_int as isize);
        dst = dst.offset(2 as libc::c_int as isize);
        len = len.wrapping_sub(1);
        if !(len != 0) {
            break;
        }
    }
}

static mut Krnd: [uint32_t; 64] = [
    0x428a2f98 as libc::c_int as uint32_t,
    0x71374491 as libc::c_int as uint32_t,
    0xb5c0fbcf as libc::c_uint,
    0xe9b5dba5 as libc::c_uint,
    0x3956c25b as libc::c_int as uint32_t,
    0x59f111f1 as libc::c_int as uint32_t,
    0x923f82a4 as libc::c_uint,
    0xab1c5ed5 as libc::c_uint,
    0xd807aa98 as libc::c_uint,
    0x12835b01 as libc::c_int as uint32_t,
    0x243185be as libc::c_int as uint32_t,
    0x550c7dc3 as libc::c_int as uint32_t,
    0x72be5d74 as libc::c_int as uint32_t,
    0x80deb1fe as libc::c_uint,
    0x9bdc06a7 as libc::c_uint,
    0xc19bf174 as libc::c_uint,
    0xe49b69c1 as libc::c_uint,
    0xefbe4786 as libc::c_uint,
    0xfc19dc6 as libc::c_int as uint32_t,
    0x240ca1cc as libc::c_int as uint32_t,
    0x2de92c6f as libc::c_int as uint32_t,
    0x4a7484aa as libc::c_int as uint32_t,
    0x5cb0a9dc as libc::c_int as uint32_t,
    0x76f988da as libc::c_int as uint32_t,
    0x983e5152 as libc::c_uint,
    0xa831c66d as libc::c_uint,
    0xb00327c8 as libc::c_uint,
    0xbf597fc7 as libc::c_uint,
    0xc6e00bf3 as libc::c_uint,
    0xd5a79147 as libc::c_uint,
    0x6ca6351 as libc::c_int as uint32_t,
    0x14292967 as libc::c_int as uint32_t,
    0x27b70a85 as libc::c_int as uint32_t,
    0x2e1b2138 as libc::c_int as uint32_t,
    0x4d2c6dfc as libc::c_int as uint32_t,
    0x53380d13 as libc::c_int as uint32_t,
    0x650a7354 as libc::c_int as uint32_t,
    0x766a0abb as libc::c_int as uint32_t,
    0x81c2c92e as libc::c_uint,
    0x92722c85 as libc::c_uint,
    0xa2bfe8a1 as libc::c_uint,
    0xa81a664b as libc::c_uint,
    0xc24b8b70 as libc::c_uint,
    0xc76c51a3 as libc::c_uint,
    0xd192e819 as libc::c_uint,
    0xd6990624 as libc::c_uint,
    0xf40e3585 as libc::c_uint,
    0x106aa070 as libc::c_int as uint32_t,
    0x19a4c116 as libc::c_int as uint32_t,
    0x1e376c08 as libc::c_int as uint32_t,
    0x2748774c as libc::c_int as uint32_t,
    0x34b0bcb5 as libc::c_int as uint32_t,
    0x391c0cb3 as libc::c_int as uint32_t,
    0x4ed8aa4a as libc::c_int as uint32_t,
    0x5b9cca4f as libc::c_int as uint32_t,
    0x682e6ff3 as libc::c_int as uint32_t,
    0x748f82ee as libc::c_int as uint32_t,
    0x78a5636f as libc::c_int as uint32_t,
    0x84c87814 as libc::c_uint,
    0x8cc70208 as libc::c_uint,
    0x90befffa as libc::c_uint,
    0xa4506ceb as libc::c_uint,
    0xbef9a3f7 as libc::c_uint,
    0xc67178f2 as libc::c_uint,
];

unsafe extern "C" fn SHA256_Transform(
    mut state: *mut uint32_t,
    mut block: *const uint8_t,
    mut W: *mut uint32_t,
    mut S: *mut uint32_t,
) {
    let mut i: libc::c_int = 0;
    be32dec_vect(W, block, 8 as libc::c_int as size_t);
    memcpy(
        S as *mut libc::c_void,
        state as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    i = 0 as libc::c_int;
    while i < 64 as libc::c_int {
        let mut x_xor_y: uint32_t = 0;
        let mut y_xor_z: uint32_t = *S
            .offset(((65 as libc::c_int - i) % 8 as libc::c_int) as isize)
            ^ *S.offset(((66 as libc::c_int - i) % 8 as libc::c_int) as isize);
        let ref mut fresh0 =
            *S.offset(((71 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh0 = (*fresh0 as libc::c_uint).wrapping_add(
            ((*S.offset(((68 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 6 as libc::c_int
                | *S.offset(((68 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize)
                    << 32 as libc::c_int - 6 as libc::c_int)
                ^ (*S
                    .offset(((68 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 11 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 11 as libc::c_int)
                ^ (*S
                    .offset(((68 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 25 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 25 as libc::c_int))
                .wrapping_add(
                    *S.offset(((68 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize)
                        & (*S.offset(
                            ((69 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize,
                        ) ^ *S.offset(
                            ((70 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize,
                        ))
                        ^ *S.offset(
                            ((70 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize,
                        ),
                )
                .wrapping_add(*W.offset((0 as libc::c_int + i) as isize))
                .wrapping_add(Krnd[(0 as libc::c_int + i) as usize]),
        ) as uint32_t as uint32_t;
        let ref mut fresh1 =
            *S.offset(((67 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh1 = (*fresh1 as libc::c_uint).wrapping_add(
            *S.offset(((71 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize),
        ) as uint32_t as uint32_t;
        x_xor_y = *S.offset(((64 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize)
            ^ *S.offset(((65 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize);
        let ref mut fresh2 =
            *S.offset(((71 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh2 = (*fresh2 as libc::c_uint).wrapping_add(
            ((*S.offset(((64 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 2 as libc::c_int
                | *S.offset(((64 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize)
                    << 32 as libc::c_int - 2 as libc::c_int)
                ^ (*S
                    .offset(((64 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 13 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 13 as libc::c_int)
                ^ (*S
                    .offset(((64 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 22 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 22 as libc::c_int))
                .wrapping_add(
                    *S.offset(((65 as libc::c_int - 0 as libc::c_int) % 8 as libc::c_int) as isize)
                        ^ x_xor_y & y_xor_z,
                ),
        ) as uint32_t as uint32_t;
        y_xor_z = x_xor_y;
        let ref mut fresh3 =
            *S.offset(((71 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh3 = (*fresh3 as libc::c_uint).wrapping_add(
            ((*S.offset(((68 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 6 as libc::c_int
                | *S.offset(((68 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize)
                    << 32 as libc::c_int - 6 as libc::c_int)
                ^ (*S
                    .offset(((68 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 11 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 11 as libc::c_int)
                ^ (*S
                    .offset(((68 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 25 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 25 as libc::c_int))
                .wrapping_add(
                    *S.offset(((68 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize)
                        & (*S.offset(
                            ((69 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize,
                        ) ^ *S.offset(
                            ((70 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize,
                        ))
                        ^ *S.offset(
                            ((70 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize,
                        ),
                )
                .wrapping_add(*W.offset((1 as libc::c_int + i) as isize))
                .wrapping_add(Krnd[(1 as libc::c_int + i) as usize]),
        ) as uint32_t as uint32_t;
        let ref mut fresh4 =
            *S.offset(((67 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh4 = (*fresh4 as libc::c_uint).wrapping_add(
            *S.offset(((71 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize),
        ) as uint32_t as uint32_t;
        x_xor_y = *S.offset(((64 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize)
            ^ *S.offset(((65 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize);
        let ref mut fresh5 =
            *S.offset(((71 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh5 = (*fresh5 as libc::c_uint).wrapping_add(
            ((*S.offset(((64 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 2 as libc::c_int
                | *S.offset(((64 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize)
                    << 32 as libc::c_int - 2 as libc::c_int)
                ^ (*S
                    .offset(((64 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 13 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 13 as libc::c_int)
                ^ (*S
                    .offset(((64 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 22 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 22 as libc::c_int))
                .wrapping_add(
                    *S.offset(((65 as libc::c_int - 1 as libc::c_int) % 8 as libc::c_int) as isize)
                        ^ x_xor_y & y_xor_z,
                ),
        ) as uint32_t as uint32_t;
        y_xor_z = x_xor_y;
        let ref mut fresh6 =
            *S.offset(((71 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh6 = (*fresh6 as libc::c_uint).wrapping_add(
            ((*S.offset(((68 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 6 as libc::c_int
                | *S.offset(((68 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize)
                    << 32 as libc::c_int - 6 as libc::c_int)
                ^ (*S
                    .offset(((68 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 11 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 11 as libc::c_int)
                ^ (*S
                    .offset(((68 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 25 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 25 as libc::c_int))
                .wrapping_add(
                    *S.offset(((68 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize)
                        & (*S.offset(
                            ((69 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize,
                        ) ^ *S.offset(
                            ((70 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize,
                        ))
                        ^ *S.offset(
                            ((70 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize,
                        ),
                )
                .wrapping_add(*W.offset((2 as libc::c_int + i) as isize))
                .wrapping_add(Krnd[(2 as libc::c_int + i) as usize]),
        ) as uint32_t as uint32_t;
        let ref mut fresh7 =
            *S.offset(((67 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh7 = (*fresh7 as libc::c_uint).wrapping_add(
            *S.offset(((71 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize),
        ) as uint32_t as uint32_t;
        x_xor_y = *S.offset(((64 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize)
            ^ *S.offset(((65 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize);
        let ref mut fresh8 =
            *S.offset(((71 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh8 = (*fresh8 as libc::c_uint).wrapping_add(
            ((*S.offset(((64 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 2 as libc::c_int
                | *S.offset(((64 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize)
                    << 32 as libc::c_int - 2 as libc::c_int)
                ^ (*S
                    .offset(((64 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 13 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 13 as libc::c_int)
                ^ (*S
                    .offset(((64 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 22 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 22 as libc::c_int))
                .wrapping_add(
                    *S.offset(((65 as libc::c_int - 2 as libc::c_int) % 8 as libc::c_int) as isize)
                        ^ x_xor_y & y_xor_z,
                ),
        ) as uint32_t as uint32_t;
        y_xor_z = x_xor_y;
        let ref mut fresh9 =
            *S.offset(((71 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh9 = (*fresh9 as libc::c_uint).wrapping_add(
            ((*S.offset(((68 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 6 as libc::c_int
                | *S.offset(((68 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize)
                    << 32 as libc::c_int - 6 as libc::c_int)
                ^ (*S
                    .offset(((68 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 11 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 11 as libc::c_int)
                ^ (*S
                    .offset(((68 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 25 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 25 as libc::c_int))
                .wrapping_add(
                    *S.offset(((68 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize)
                        & (*S.offset(
                            ((69 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize,
                        ) ^ *S.offset(
                            ((70 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize,
                        ))
                        ^ *S.offset(
                            ((70 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize,
                        ),
                )
                .wrapping_add(*W.offset((3 as libc::c_int + i) as isize))
                .wrapping_add(Krnd[(3 as libc::c_int + i) as usize]),
        ) as uint32_t as uint32_t;
        let ref mut fresh10 =
            *S.offset(((67 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh10 = (*fresh10 as libc::c_uint).wrapping_add(
            *S.offset(((71 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize),
        ) as uint32_t as uint32_t;
        x_xor_y = *S.offset(((64 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize)
            ^ *S.offset(((65 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize);
        let ref mut fresh11 =
            *S.offset(((71 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh11 = (*fresh11 as libc::c_uint).wrapping_add(
            ((*S.offset(((64 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 2 as libc::c_int
                | *S.offset(((64 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize)
                    << 32 as libc::c_int - 2 as libc::c_int)
                ^ (*S
                    .offset(((64 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 13 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 13 as libc::c_int)
                ^ (*S
                    .offset(((64 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 22 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 22 as libc::c_int))
                .wrapping_add(
                    *S.offset(((65 as libc::c_int - 3 as libc::c_int) % 8 as libc::c_int) as isize)
                        ^ x_xor_y & y_xor_z,
                ),
        ) as uint32_t as uint32_t;
        y_xor_z = x_xor_y;
        let ref mut fresh12 =
            *S.offset(((71 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh12 = (*fresh12 as libc::c_uint).wrapping_add(
            ((*S.offset(((68 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 6 as libc::c_int
                | *S.offset(((68 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize)
                    << 32 as libc::c_int - 6 as libc::c_int)
                ^ (*S
                    .offset(((68 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 11 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 11 as libc::c_int)
                ^ (*S
                    .offset(((68 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 25 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 25 as libc::c_int))
                .wrapping_add(
                    *S.offset(((68 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize)
                        & (*S.offset(
                            ((69 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize,
                        ) ^ *S.offset(
                            ((70 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize,
                        ))
                        ^ *S.offset(
                            ((70 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize,
                        ),
                )
                .wrapping_add(*W.offset((4 as libc::c_int + i) as isize))
                .wrapping_add(Krnd[(4 as libc::c_int + i) as usize]),
        ) as uint32_t as uint32_t;
        let ref mut fresh13 =
            *S.offset(((67 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh13 = (*fresh13 as libc::c_uint).wrapping_add(
            *S.offset(((71 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize),
        ) as uint32_t as uint32_t;
        x_xor_y = *S.offset(((64 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize)
            ^ *S.offset(((65 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize);
        let ref mut fresh14 =
            *S.offset(((71 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh14 = (*fresh14 as libc::c_uint).wrapping_add(
            ((*S.offset(((64 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 2 as libc::c_int
                | *S.offset(((64 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize)
                    << 32 as libc::c_int - 2 as libc::c_int)
                ^ (*S
                    .offset(((64 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 13 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 13 as libc::c_int)
                ^ (*S
                    .offset(((64 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 22 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 22 as libc::c_int))
                .wrapping_add(
                    *S.offset(((65 as libc::c_int - 4 as libc::c_int) % 8 as libc::c_int) as isize)
                        ^ x_xor_y & y_xor_z,
                ),
        ) as uint32_t as uint32_t;
        y_xor_z = x_xor_y;
        let ref mut fresh15 =
            *S.offset(((71 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh15 = (*fresh15 as libc::c_uint).wrapping_add(
            ((*S.offset(((68 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 6 as libc::c_int
                | *S.offset(((68 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize)
                    << 32 as libc::c_int - 6 as libc::c_int)
                ^ (*S
                    .offset(((68 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 11 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 11 as libc::c_int)
                ^ (*S
                    .offset(((68 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 25 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 25 as libc::c_int))
                .wrapping_add(
                    *S.offset(((68 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize)
                        & (*S.offset(
                            ((69 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize,
                        ) ^ *S.offset(
                            ((70 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize,
                        ))
                        ^ *S.offset(
                            ((70 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize,
                        ),
                )
                .wrapping_add(*W.offset((5 as libc::c_int + i) as isize))
                .wrapping_add(Krnd[(5 as libc::c_int + i) as usize]),
        ) as uint32_t as uint32_t;
        let ref mut fresh16 =
            *S.offset(((67 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh16 = (*fresh16 as libc::c_uint).wrapping_add(
            *S.offset(((71 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize),
        ) as uint32_t as uint32_t;
        x_xor_y = *S.offset(((64 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize)
            ^ *S.offset(((65 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize);
        let ref mut fresh17 =
            *S.offset(((71 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh17 = (*fresh17 as libc::c_uint).wrapping_add(
            ((*S.offset(((64 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 2 as libc::c_int
                | *S.offset(((64 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize)
                    << 32 as libc::c_int - 2 as libc::c_int)
                ^ (*S
                    .offset(((64 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 13 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 13 as libc::c_int)
                ^ (*S
                    .offset(((64 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 22 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 22 as libc::c_int))
                .wrapping_add(
                    *S.offset(((65 as libc::c_int - 5 as libc::c_int) % 8 as libc::c_int) as isize)
                        ^ x_xor_y & y_xor_z,
                ),
        ) as uint32_t as uint32_t;
        y_xor_z = x_xor_y;
        let ref mut fresh18 =
            *S.offset(((71 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh18 = (*fresh18 as libc::c_uint).wrapping_add(
            ((*S.offset(((68 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 6 as libc::c_int
                | *S.offset(((68 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize)
                    << 32 as libc::c_int - 6 as libc::c_int)
                ^ (*S
                    .offset(((68 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 11 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 11 as libc::c_int)
                ^ (*S
                    .offset(((68 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 25 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 25 as libc::c_int))
                .wrapping_add(
                    *S.offset(((68 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize)
                        & (*S.offset(
                            ((69 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize,
                        ) ^ *S.offset(
                            ((70 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize,
                        ))
                        ^ *S.offset(
                            ((70 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize,
                        ),
                )
                .wrapping_add(*W.offset((6 as libc::c_int + i) as isize))
                .wrapping_add(Krnd[(6 as libc::c_int + i) as usize]),
        ) as uint32_t as uint32_t;
        let ref mut fresh19 =
            *S.offset(((67 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh19 = (*fresh19 as libc::c_uint).wrapping_add(
            *S.offset(((71 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize),
        ) as uint32_t as uint32_t;
        x_xor_y = *S.offset(((64 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize)
            ^ *S.offset(((65 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize);
        let ref mut fresh20 =
            *S.offset(((71 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh20 = (*fresh20 as libc::c_uint).wrapping_add(
            ((*S.offset(((64 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 2 as libc::c_int
                | *S.offset(((64 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize)
                    << 32 as libc::c_int - 2 as libc::c_int)
                ^ (*S
                    .offset(((64 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 13 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 13 as libc::c_int)
                ^ (*S
                    .offset(((64 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 22 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 22 as libc::c_int))
                .wrapping_add(
                    *S.offset(((65 as libc::c_int - 6 as libc::c_int) % 8 as libc::c_int) as isize)
                        ^ x_xor_y & y_xor_z,
                ),
        ) as uint32_t as uint32_t;
        y_xor_z = x_xor_y;
        let ref mut fresh21 =
            *S.offset(((71 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh21 = (*fresh21 as libc::c_uint).wrapping_add(
            ((*S.offset(((68 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 6 as libc::c_int
                | *S.offset(((68 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize)
                    << 32 as libc::c_int - 6 as libc::c_int)
                ^ (*S
                    .offset(((68 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 11 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 11 as libc::c_int)
                ^ (*S
                    .offset(((68 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 25 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 25 as libc::c_int))
                .wrapping_add(
                    *S.offset(((68 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize)
                        & (*S.offset(
                            ((69 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize,
                        ) ^ *S.offset(
                            ((70 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize,
                        ))
                        ^ *S.offset(
                            ((70 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize,
                        ),
                )
                .wrapping_add(*W.offset((7 as libc::c_int + i) as isize))
                .wrapping_add(Krnd[(7 as libc::c_int + i) as usize]),
        ) as uint32_t as uint32_t;
        let ref mut fresh22 =
            *S.offset(((67 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh22 = (*fresh22 as libc::c_uint).wrapping_add(
            *S.offset(((71 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize),
        ) as uint32_t as uint32_t;
        x_xor_y = *S.offset(((64 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize)
            ^ *S.offset(((65 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize);
        let ref mut fresh23 =
            *S.offset(((71 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh23 = (*fresh23 as libc::c_uint).wrapping_add(
            ((*S.offset(((64 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 2 as libc::c_int
                | *S.offset(((64 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize)
                    << 32 as libc::c_int - 2 as libc::c_int)
                ^ (*S
                    .offset(((64 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 13 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 13 as libc::c_int)
                ^ (*S
                    .offset(((64 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 22 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 22 as libc::c_int))
                .wrapping_add(
                    *S.offset(((65 as libc::c_int - 7 as libc::c_int) % 8 as libc::c_int) as isize)
                        ^ x_xor_y & y_xor_z,
                ),
        ) as uint32_t as uint32_t;
        y_xor_z = x_xor_y;
        let ref mut fresh24 =
            *S.offset(((71 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh24 = (*fresh24 as libc::c_uint).wrapping_add(
            ((*S.offset(((68 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 6 as libc::c_int
                | *S.offset(((68 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize)
                    << 32 as libc::c_int - 6 as libc::c_int)
                ^ (*S
                    .offset(((68 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 11 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 11 as libc::c_int)
                ^ (*S
                    .offset(((68 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 25 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 25 as libc::c_int))
                .wrapping_add(
                    *S.offset(((68 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize)
                        & (*S.offset(
                            ((69 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize,
                        ) ^ *S.offset(
                            ((70 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize,
                        ))
                        ^ *S.offset(
                            ((70 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize,
                        ),
                )
                .wrapping_add(*W.offset((8 as libc::c_int + i) as isize))
                .wrapping_add(Krnd[(8 as libc::c_int + i) as usize]),
        ) as uint32_t as uint32_t;
        let ref mut fresh25 =
            *S.offset(((67 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh25 = (*fresh25 as libc::c_uint).wrapping_add(
            *S.offset(((71 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize),
        ) as uint32_t as uint32_t;
        x_xor_y = *S.offset(((64 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize)
            ^ *S.offset(((65 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize);
        let ref mut fresh26 =
            *S.offset(((71 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh26 = (*fresh26 as libc::c_uint).wrapping_add(
            ((*S.offset(((64 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 2 as libc::c_int
                | *S.offset(((64 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize)
                    << 32 as libc::c_int - 2 as libc::c_int)
                ^ (*S
                    .offset(((64 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 13 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 13 as libc::c_int)
                ^ (*S
                    .offset(((64 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 22 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 22 as libc::c_int))
                .wrapping_add(
                    *S.offset(((65 as libc::c_int - 8 as libc::c_int) % 8 as libc::c_int) as isize)
                        ^ x_xor_y & y_xor_z,
                ),
        ) as uint32_t as uint32_t;
        y_xor_z = x_xor_y;
        let ref mut fresh27 =
            *S.offset(((71 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh27 = (*fresh27 as libc::c_uint).wrapping_add(
            ((*S.offset(((68 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 6 as libc::c_int
                | *S.offset(((68 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize)
                    << 32 as libc::c_int - 6 as libc::c_int)
                ^ (*S
                    .offset(((68 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 11 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 11 as libc::c_int)
                ^ (*S
                    .offset(((68 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 25 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 25 as libc::c_int))
                .wrapping_add(
                    *S.offset(((68 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize)
                        & (*S.offset(
                            ((69 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize,
                        ) ^ *S.offset(
                            ((70 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize,
                        ))
                        ^ *S.offset(
                            ((70 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize,
                        ),
                )
                .wrapping_add(*W.offset((9 as libc::c_int + i) as isize))
                .wrapping_add(Krnd[(9 as libc::c_int + i) as usize]),
        ) as uint32_t as uint32_t;
        let ref mut fresh28 =
            *S.offset(((67 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh28 = (*fresh28 as libc::c_uint).wrapping_add(
            *S.offset(((71 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize),
        ) as uint32_t as uint32_t;
        x_xor_y = *S.offset(((64 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize)
            ^ *S.offset(((65 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize);
        let ref mut fresh29 =
            *S.offset(((71 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh29 = (*fresh29 as libc::c_uint).wrapping_add(
            ((*S.offset(((64 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 2 as libc::c_int
                | *S.offset(((64 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize)
                    << 32 as libc::c_int - 2 as libc::c_int)
                ^ (*S
                    .offset(((64 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 13 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 13 as libc::c_int)
                ^ (*S
                    .offset(((64 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize)
                    >> 22 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 22 as libc::c_int))
                .wrapping_add(
                    *S.offset(((65 as libc::c_int - 9 as libc::c_int) % 8 as libc::c_int) as isize)
                        ^ x_xor_y & y_xor_z,
                ),
        ) as uint32_t as uint32_t;
        y_xor_z = x_xor_y;
        let ref mut fresh30 =
            *S.offset(((71 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh30 = (*fresh30 as libc::c_uint).wrapping_add(
            ((*S.offset(((68 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 6 as libc::c_int
                | *S.offset(
                    ((68 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize,
                ) << 32 as libc::c_int - 6 as libc::c_int)
                ^ (*S.offset(
                    ((68 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 11 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 11 as libc::c_int)
                ^ (*S.offset(
                    ((68 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 25 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 25 as libc::c_int))
                .wrapping_add(
                    *S.offset(
                        ((68 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) & (*S.offset(
                        ((69 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) ^ *S.offset(
                        ((70 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize,
                    )) ^ *S.offset(
                        ((70 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize,
                    ),
                )
                .wrapping_add(*W.offset((10 as libc::c_int + i) as isize))
                .wrapping_add(Krnd[(10 as libc::c_int + i) as usize]),
        ) as uint32_t as uint32_t;
        let ref mut fresh31 =
            *S.offset(((67 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh31 = (*fresh31 as libc::c_uint).wrapping_add(
            *S.offset(((71 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize),
        ) as uint32_t as uint32_t;
        x_xor_y = *S.offset(((64 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize)
            ^ *S.offset(((65 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize);
        let ref mut fresh32 =
            *S.offset(((71 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh32 = (*fresh32 as libc::c_uint).wrapping_add(
            ((*S.offset(((64 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 2 as libc::c_int
                | *S.offset(
                    ((64 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize,
                ) << 32 as libc::c_int - 2 as libc::c_int)
                ^ (*S.offset(
                    ((64 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 13 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 13 as libc::c_int)
                ^ (*S.offset(
                    ((64 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 22 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 22 as libc::c_int))
                .wrapping_add(
                    *S.offset(
                        ((65 as libc::c_int - 10 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) ^ x_xor_y & y_xor_z,
                ),
        ) as uint32_t as uint32_t;
        y_xor_z = x_xor_y;
        let ref mut fresh33 =
            *S.offset(((71 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh33 = (*fresh33 as libc::c_uint).wrapping_add(
            ((*S.offset(((68 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 6 as libc::c_int
                | *S.offset(
                    ((68 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize,
                ) << 32 as libc::c_int - 6 as libc::c_int)
                ^ (*S.offset(
                    ((68 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 11 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 11 as libc::c_int)
                ^ (*S.offset(
                    ((68 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 25 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 25 as libc::c_int))
                .wrapping_add(
                    *S.offset(
                        ((68 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) & (*S.offset(
                        ((69 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) ^ *S.offset(
                        ((70 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize,
                    )) ^ *S.offset(
                        ((70 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize,
                    ),
                )
                .wrapping_add(*W.offset((11 as libc::c_int + i) as isize))
                .wrapping_add(Krnd[(11 as libc::c_int + i) as usize]),
        ) as uint32_t as uint32_t;
        let ref mut fresh34 =
            *S.offset(((67 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh34 = (*fresh34 as libc::c_uint).wrapping_add(
            *S.offset(((71 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize),
        ) as uint32_t as uint32_t;
        x_xor_y = *S.offset(((64 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize)
            ^ *S.offset(((65 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize);
        let ref mut fresh35 =
            *S.offset(((71 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh35 = (*fresh35 as libc::c_uint).wrapping_add(
            ((*S.offset(((64 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 2 as libc::c_int
                | *S.offset(
                    ((64 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize,
                ) << 32 as libc::c_int - 2 as libc::c_int)
                ^ (*S.offset(
                    ((64 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 13 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 13 as libc::c_int)
                ^ (*S.offset(
                    ((64 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 22 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 22 as libc::c_int))
                .wrapping_add(
                    *S.offset(
                        ((65 as libc::c_int - 11 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) ^ x_xor_y & y_xor_z,
                ),
        ) as uint32_t as uint32_t;
        y_xor_z = x_xor_y;
        let ref mut fresh36 =
            *S.offset(((71 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh36 = (*fresh36 as libc::c_uint).wrapping_add(
            ((*S.offset(((68 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 6 as libc::c_int
                | *S.offset(
                    ((68 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize,
                ) << 32 as libc::c_int - 6 as libc::c_int)
                ^ (*S.offset(
                    ((68 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 11 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 11 as libc::c_int)
                ^ (*S.offset(
                    ((68 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 25 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 25 as libc::c_int))
                .wrapping_add(
                    *S.offset(
                        ((68 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) & (*S.offset(
                        ((69 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) ^ *S.offset(
                        ((70 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize,
                    )) ^ *S.offset(
                        ((70 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize,
                    ),
                )
                .wrapping_add(*W.offset((12 as libc::c_int + i) as isize))
                .wrapping_add(Krnd[(12 as libc::c_int + i) as usize]),
        ) as uint32_t as uint32_t;
        let ref mut fresh37 =
            *S.offset(((67 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh37 = (*fresh37 as libc::c_uint).wrapping_add(
            *S.offset(((71 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize),
        ) as uint32_t as uint32_t;
        x_xor_y = *S.offset(((64 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize)
            ^ *S.offset(((65 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize);
        let ref mut fresh38 =
            *S.offset(((71 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh38 = (*fresh38 as libc::c_uint).wrapping_add(
            ((*S.offset(((64 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 2 as libc::c_int
                | *S.offset(
                    ((64 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize,
                ) << 32 as libc::c_int - 2 as libc::c_int)
                ^ (*S.offset(
                    ((64 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 13 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 13 as libc::c_int)
                ^ (*S.offset(
                    ((64 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 22 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 22 as libc::c_int))
                .wrapping_add(
                    *S.offset(
                        ((65 as libc::c_int - 12 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) ^ x_xor_y & y_xor_z,
                ),
        ) as uint32_t as uint32_t;
        y_xor_z = x_xor_y;
        let ref mut fresh39 =
            *S.offset(((71 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh39 = (*fresh39 as libc::c_uint).wrapping_add(
            ((*S.offset(((68 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 6 as libc::c_int
                | *S.offset(
                    ((68 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize,
                ) << 32 as libc::c_int - 6 as libc::c_int)
                ^ (*S.offset(
                    ((68 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 11 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 11 as libc::c_int)
                ^ (*S.offset(
                    ((68 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 25 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 25 as libc::c_int))
                .wrapping_add(
                    *S.offset(
                        ((68 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) & (*S.offset(
                        ((69 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) ^ *S.offset(
                        ((70 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize,
                    )) ^ *S.offset(
                        ((70 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize,
                    ),
                )
                .wrapping_add(*W.offset((13 as libc::c_int + i) as isize))
                .wrapping_add(Krnd[(13 as libc::c_int + i) as usize]),
        ) as uint32_t as uint32_t;
        let ref mut fresh40 =
            *S.offset(((67 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh40 = (*fresh40 as libc::c_uint).wrapping_add(
            *S.offset(((71 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize),
        ) as uint32_t as uint32_t;
        x_xor_y = *S.offset(((64 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize)
            ^ *S.offset(((65 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize);
        let ref mut fresh41 =
            *S.offset(((71 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh41 = (*fresh41 as libc::c_uint).wrapping_add(
            ((*S.offset(((64 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 2 as libc::c_int
                | *S.offset(
                    ((64 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize,
                ) << 32 as libc::c_int - 2 as libc::c_int)
                ^ (*S.offset(
                    ((64 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 13 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 13 as libc::c_int)
                ^ (*S.offset(
                    ((64 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 22 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 22 as libc::c_int))
                .wrapping_add(
                    *S.offset(
                        ((65 as libc::c_int - 13 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) ^ x_xor_y & y_xor_z,
                ),
        ) as uint32_t as uint32_t;
        y_xor_z = x_xor_y;
        let ref mut fresh42 =
            *S.offset(((71 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh42 = (*fresh42 as libc::c_uint).wrapping_add(
            ((*S.offset(((68 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 6 as libc::c_int
                | *S.offset(
                    ((68 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize,
                ) << 32 as libc::c_int - 6 as libc::c_int)
                ^ (*S.offset(
                    ((68 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 11 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 11 as libc::c_int)
                ^ (*S.offset(
                    ((68 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 25 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 25 as libc::c_int))
                .wrapping_add(
                    *S.offset(
                        ((68 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) & (*S.offset(
                        ((69 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) ^ *S.offset(
                        ((70 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize,
                    )) ^ *S.offset(
                        ((70 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize,
                    ),
                )
                .wrapping_add(*W.offset((14 as libc::c_int + i) as isize))
                .wrapping_add(Krnd[(14 as libc::c_int + i) as usize]),
        ) as uint32_t as uint32_t;
        let ref mut fresh43 =
            *S.offset(((67 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh43 = (*fresh43 as libc::c_uint).wrapping_add(
            *S.offset(((71 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize),
        ) as uint32_t as uint32_t;
        x_xor_y = *S.offset(((64 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize)
            ^ *S.offset(((65 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize);
        let ref mut fresh44 =
            *S.offset(((71 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh44 = (*fresh44 as libc::c_uint).wrapping_add(
            ((*S.offset(((64 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 2 as libc::c_int
                | *S.offset(
                    ((64 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize,
                ) << 32 as libc::c_int - 2 as libc::c_int)
                ^ (*S.offset(
                    ((64 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 13 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 13 as libc::c_int)
                ^ (*S.offset(
                    ((64 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 22 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 22 as libc::c_int))
                .wrapping_add(
                    *S.offset(
                        ((65 as libc::c_int - 14 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) ^ x_xor_y & y_xor_z,
                ),
        ) as uint32_t as uint32_t;
        y_xor_z = x_xor_y;
        let ref mut fresh45 =
            *S.offset(((71 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh45 = (*fresh45 as libc::c_uint).wrapping_add(
            ((*S.offset(((68 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 6 as libc::c_int
                | *S.offset(
                    ((68 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize,
                ) << 32 as libc::c_int - 6 as libc::c_int)
                ^ (*S.offset(
                    ((68 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 11 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 11 as libc::c_int)
                ^ (*S.offset(
                    ((68 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 25 as libc::c_int
                    | *S.offset(
                        ((68 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 25 as libc::c_int))
                .wrapping_add(
                    *S.offset(
                        ((68 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) & (*S.offset(
                        ((69 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) ^ *S.offset(
                        ((70 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize,
                    )) ^ *S.offset(
                        ((70 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize,
                    ),
                )
                .wrapping_add(*W.offset((15 as libc::c_int + i) as isize))
                .wrapping_add(Krnd[(15 as libc::c_int + i) as usize]),
        ) as uint32_t as uint32_t;
        let ref mut fresh46 =
            *S.offset(((67 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh46 = (*fresh46 as libc::c_uint).wrapping_add(
            *S.offset(((71 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize),
        ) as uint32_t as uint32_t;
        x_xor_y = *S.offset(((64 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize)
            ^ *S.offset(((65 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize);
        let ref mut fresh47 =
            *S.offset(((71 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize);
        *fresh47 = (*fresh47 as libc::c_uint).wrapping_add(
            ((*S.offset(((64 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize)
                >> 2 as libc::c_int
                | *S.offset(
                    ((64 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize,
                ) << 32 as libc::c_int - 2 as libc::c_int)
                ^ (*S.offset(
                    ((64 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 13 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 13 as libc::c_int)
                ^ (*S.offset(
                    ((64 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize,
                ) >> 22 as libc::c_int
                    | *S.offset(
                        ((64 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) << 32 as libc::c_int - 22 as libc::c_int))
                .wrapping_add(
                    *S.offset(
                        ((65 as libc::c_int - 15 as libc::c_int) % 8 as libc::c_int) as isize,
                    ) ^ x_xor_y & y_xor_z,
                ),
        ) as uint32_t as uint32_t;
        y_xor_z = x_xor_y;
        if i == 48 as libc::c_int {
            break;
        }
        *W.offset((i + 0 as libc::c_int + 16 as libc::c_int) as isize) = ((*W
            .offset((i + 0 as libc::c_int + 14 as libc::c_int) as isize)
            >> 17 as libc::c_int
            | *W.offset((i + 0 as libc::c_int + 14 as libc::c_int) as isize)
                << 32 as libc::c_int - 17 as libc::c_int)
            ^ (*W.offset((i + 0 as libc::c_int + 14 as libc::c_int) as isize)
                >> 19 as libc::c_int
                | *W.offset((i + 0 as libc::c_int + 14 as libc::c_int) as isize)
                    << 32 as libc::c_int - 19 as libc::c_int)
            ^ *W.offset((i + 0 as libc::c_int + 14 as libc::c_int) as isize) >> 10 as libc::c_int)
            .wrapping_add(*W.offset((i + 0 as libc::c_int + 9 as libc::c_int) as isize))
            .wrapping_add(
                (*W.offset((i + 0 as libc::c_int + 1 as libc::c_int) as isize) >> 7 as libc::c_int
                    | *W.offset((i + 0 as libc::c_int + 1 as libc::c_int) as isize)
                        << 32 as libc::c_int - 7 as libc::c_int)
                    ^ (*W.offset((i + 0 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 18 as libc::c_int
                        | *W.offset((i + 0 as libc::c_int + 1 as libc::c_int) as isize)
                            << 32 as libc::c_int - 18 as libc::c_int)
                    ^ *W.offset((i + 0 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 3 as libc::c_int,
            )
            .wrapping_add(*W.offset((i + 0 as libc::c_int) as isize));
        *W.offset((i + 1 as libc::c_int + 16 as libc::c_int) as isize) = ((*W
            .offset((i + 1 as libc::c_int + 14 as libc::c_int) as isize)
            >> 17 as libc::c_int
            | *W.offset((i + 1 as libc::c_int + 14 as libc::c_int) as isize)
                << 32 as libc::c_int - 17 as libc::c_int)
            ^ (*W.offset((i + 1 as libc::c_int + 14 as libc::c_int) as isize)
                >> 19 as libc::c_int
                | *W.offset((i + 1 as libc::c_int + 14 as libc::c_int) as isize)
                    << 32 as libc::c_int - 19 as libc::c_int)
            ^ *W.offset((i + 1 as libc::c_int + 14 as libc::c_int) as isize) >> 10 as libc::c_int)
            .wrapping_add(*W.offset((i + 1 as libc::c_int + 9 as libc::c_int) as isize))
            .wrapping_add(
                (*W.offset((i + 1 as libc::c_int + 1 as libc::c_int) as isize) >> 7 as libc::c_int
                    | *W.offset((i + 1 as libc::c_int + 1 as libc::c_int) as isize)
                        << 32 as libc::c_int - 7 as libc::c_int)
                    ^ (*W.offset((i + 1 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 18 as libc::c_int
                        | *W.offset((i + 1 as libc::c_int + 1 as libc::c_int) as isize)
                            << 32 as libc::c_int - 18 as libc::c_int)
                    ^ *W.offset((i + 1 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 3 as libc::c_int,
            )
            .wrapping_add(*W.offset((i + 1 as libc::c_int) as isize));
        *W.offset((i + 2 as libc::c_int + 16 as libc::c_int) as isize) = ((*W
            .offset((i + 2 as libc::c_int + 14 as libc::c_int) as isize)
            >> 17 as libc::c_int
            | *W.offset((i + 2 as libc::c_int + 14 as libc::c_int) as isize)
                << 32 as libc::c_int - 17 as libc::c_int)
            ^ (*W.offset((i + 2 as libc::c_int + 14 as libc::c_int) as isize)
                >> 19 as libc::c_int
                | *W.offset((i + 2 as libc::c_int + 14 as libc::c_int) as isize)
                    << 32 as libc::c_int - 19 as libc::c_int)
            ^ *W.offset((i + 2 as libc::c_int + 14 as libc::c_int) as isize) >> 10 as libc::c_int)
            .wrapping_add(*W.offset((i + 2 as libc::c_int + 9 as libc::c_int) as isize))
            .wrapping_add(
                (*W.offset((i + 2 as libc::c_int + 1 as libc::c_int) as isize) >> 7 as libc::c_int
                    | *W.offset((i + 2 as libc::c_int + 1 as libc::c_int) as isize)
                        << 32 as libc::c_int - 7 as libc::c_int)
                    ^ (*W.offset((i + 2 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 18 as libc::c_int
                        | *W.offset((i + 2 as libc::c_int + 1 as libc::c_int) as isize)
                            << 32 as libc::c_int - 18 as libc::c_int)
                    ^ *W.offset((i + 2 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 3 as libc::c_int,
            )
            .wrapping_add(*W.offset((i + 2 as libc::c_int) as isize));
        *W.offset((i + 3 as libc::c_int + 16 as libc::c_int) as isize) = ((*W
            .offset((i + 3 as libc::c_int + 14 as libc::c_int) as isize)
            >> 17 as libc::c_int
            | *W.offset((i + 3 as libc::c_int + 14 as libc::c_int) as isize)
                << 32 as libc::c_int - 17 as libc::c_int)
            ^ (*W.offset((i + 3 as libc::c_int + 14 as libc::c_int) as isize)
                >> 19 as libc::c_int
                | *W.offset((i + 3 as libc::c_int + 14 as libc::c_int) as isize)
                    << 32 as libc::c_int - 19 as libc::c_int)
            ^ *W.offset((i + 3 as libc::c_int + 14 as libc::c_int) as isize) >> 10 as libc::c_int)
            .wrapping_add(*W.offset((i + 3 as libc::c_int + 9 as libc::c_int) as isize))
            .wrapping_add(
                (*W.offset((i + 3 as libc::c_int + 1 as libc::c_int) as isize) >> 7 as libc::c_int
                    | *W.offset((i + 3 as libc::c_int + 1 as libc::c_int) as isize)
                        << 32 as libc::c_int - 7 as libc::c_int)
                    ^ (*W.offset((i + 3 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 18 as libc::c_int
                        | *W.offset((i + 3 as libc::c_int + 1 as libc::c_int) as isize)
                            << 32 as libc::c_int - 18 as libc::c_int)
                    ^ *W.offset((i + 3 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 3 as libc::c_int,
            )
            .wrapping_add(*W.offset((i + 3 as libc::c_int) as isize));
        *W.offset((i + 4 as libc::c_int + 16 as libc::c_int) as isize) = ((*W
            .offset((i + 4 as libc::c_int + 14 as libc::c_int) as isize)
            >> 17 as libc::c_int
            | *W.offset((i + 4 as libc::c_int + 14 as libc::c_int) as isize)
                << 32 as libc::c_int - 17 as libc::c_int)
            ^ (*W.offset((i + 4 as libc::c_int + 14 as libc::c_int) as isize)
                >> 19 as libc::c_int
                | *W.offset((i + 4 as libc::c_int + 14 as libc::c_int) as isize)
                    << 32 as libc::c_int - 19 as libc::c_int)
            ^ *W.offset((i + 4 as libc::c_int + 14 as libc::c_int) as isize) >> 10 as libc::c_int)
            .wrapping_add(*W.offset((i + 4 as libc::c_int + 9 as libc::c_int) as isize))
            .wrapping_add(
                (*W.offset((i + 4 as libc::c_int + 1 as libc::c_int) as isize) >> 7 as libc::c_int
                    | *W.offset((i + 4 as libc::c_int + 1 as libc::c_int) as isize)
                        << 32 as libc::c_int - 7 as libc::c_int)
                    ^ (*W.offset((i + 4 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 18 as libc::c_int
                        | *W.offset((i + 4 as libc::c_int + 1 as libc::c_int) as isize)
                            << 32 as libc::c_int - 18 as libc::c_int)
                    ^ *W.offset((i + 4 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 3 as libc::c_int,
            )
            .wrapping_add(*W.offset((i + 4 as libc::c_int) as isize));
        *W.offset((i + 5 as libc::c_int + 16 as libc::c_int) as isize) = ((*W
            .offset((i + 5 as libc::c_int + 14 as libc::c_int) as isize)
            >> 17 as libc::c_int
            | *W.offset((i + 5 as libc::c_int + 14 as libc::c_int) as isize)
                << 32 as libc::c_int - 17 as libc::c_int)
            ^ (*W.offset((i + 5 as libc::c_int + 14 as libc::c_int) as isize)
                >> 19 as libc::c_int
                | *W.offset((i + 5 as libc::c_int + 14 as libc::c_int) as isize)
                    << 32 as libc::c_int - 19 as libc::c_int)
            ^ *W.offset((i + 5 as libc::c_int + 14 as libc::c_int) as isize) >> 10 as libc::c_int)
            .wrapping_add(*W.offset((i + 5 as libc::c_int + 9 as libc::c_int) as isize))
            .wrapping_add(
                (*W.offset((i + 5 as libc::c_int + 1 as libc::c_int) as isize) >> 7 as libc::c_int
                    | *W.offset((i + 5 as libc::c_int + 1 as libc::c_int) as isize)
                        << 32 as libc::c_int - 7 as libc::c_int)
                    ^ (*W.offset((i + 5 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 18 as libc::c_int
                        | *W.offset((i + 5 as libc::c_int + 1 as libc::c_int) as isize)
                            << 32 as libc::c_int - 18 as libc::c_int)
                    ^ *W.offset((i + 5 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 3 as libc::c_int,
            )
            .wrapping_add(*W.offset((i + 5 as libc::c_int) as isize));
        *W.offset((i + 6 as libc::c_int + 16 as libc::c_int) as isize) = ((*W
            .offset((i + 6 as libc::c_int + 14 as libc::c_int) as isize)
            >> 17 as libc::c_int
            | *W.offset((i + 6 as libc::c_int + 14 as libc::c_int) as isize)
                << 32 as libc::c_int - 17 as libc::c_int)
            ^ (*W.offset((i + 6 as libc::c_int + 14 as libc::c_int) as isize)
                >> 19 as libc::c_int
                | *W.offset((i + 6 as libc::c_int + 14 as libc::c_int) as isize)
                    << 32 as libc::c_int - 19 as libc::c_int)
            ^ *W.offset((i + 6 as libc::c_int + 14 as libc::c_int) as isize) >> 10 as libc::c_int)
            .wrapping_add(*W.offset((i + 6 as libc::c_int + 9 as libc::c_int) as isize))
            .wrapping_add(
                (*W.offset((i + 6 as libc::c_int + 1 as libc::c_int) as isize) >> 7 as libc::c_int
                    | *W.offset((i + 6 as libc::c_int + 1 as libc::c_int) as isize)
                        << 32 as libc::c_int - 7 as libc::c_int)
                    ^ (*W.offset((i + 6 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 18 as libc::c_int
                        | *W.offset((i + 6 as libc::c_int + 1 as libc::c_int) as isize)
                            << 32 as libc::c_int - 18 as libc::c_int)
                    ^ *W.offset((i + 6 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 3 as libc::c_int,
            )
            .wrapping_add(*W.offset((i + 6 as libc::c_int) as isize));
        *W.offset((i + 7 as libc::c_int + 16 as libc::c_int) as isize) = ((*W
            .offset((i + 7 as libc::c_int + 14 as libc::c_int) as isize)
            >> 17 as libc::c_int
            | *W.offset((i + 7 as libc::c_int + 14 as libc::c_int) as isize)
                << 32 as libc::c_int - 17 as libc::c_int)
            ^ (*W.offset((i + 7 as libc::c_int + 14 as libc::c_int) as isize)
                >> 19 as libc::c_int
                | *W.offset((i + 7 as libc::c_int + 14 as libc::c_int) as isize)
                    << 32 as libc::c_int - 19 as libc::c_int)
            ^ *W.offset((i + 7 as libc::c_int + 14 as libc::c_int) as isize) >> 10 as libc::c_int)
            .wrapping_add(*W.offset((i + 7 as libc::c_int + 9 as libc::c_int) as isize))
            .wrapping_add(
                (*W.offset((i + 7 as libc::c_int + 1 as libc::c_int) as isize) >> 7 as libc::c_int
                    | *W.offset((i + 7 as libc::c_int + 1 as libc::c_int) as isize)
                        << 32 as libc::c_int - 7 as libc::c_int)
                    ^ (*W.offset((i + 7 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 18 as libc::c_int
                        | *W.offset((i + 7 as libc::c_int + 1 as libc::c_int) as isize)
                            << 32 as libc::c_int - 18 as libc::c_int)
                    ^ *W.offset((i + 7 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 3 as libc::c_int,
            )
            .wrapping_add(*W.offset((i + 7 as libc::c_int) as isize));
        *W.offset((i + 8 as libc::c_int + 16 as libc::c_int) as isize) = ((*W
            .offset((i + 8 as libc::c_int + 14 as libc::c_int) as isize)
            >> 17 as libc::c_int
            | *W.offset((i + 8 as libc::c_int + 14 as libc::c_int) as isize)
                << 32 as libc::c_int - 17 as libc::c_int)
            ^ (*W.offset((i + 8 as libc::c_int + 14 as libc::c_int) as isize)
                >> 19 as libc::c_int
                | *W.offset((i + 8 as libc::c_int + 14 as libc::c_int) as isize)
                    << 32 as libc::c_int - 19 as libc::c_int)
            ^ *W.offset((i + 8 as libc::c_int + 14 as libc::c_int) as isize) >> 10 as libc::c_int)
            .wrapping_add(*W.offset((i + 8 as libc::c_int + 9 as libc::c_int) as isize))
            .wrapping_add(
                (*W.offset((i + 8 as libc::c_int + 1 as libc::c_int) as isize) >> 7 as libc::c_int
                    | *W.offset((i + 8 as libc::c_int + 1 as libc::c_int) as isize)
                        << 32 as libc::c_int - 7 as libc::c_int)
                    ^ (*W.offset((i + 8 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 18 as libc::c_int
                        | *W.offset((i + 8 as libc::c_int + 1 as libc::c_int) as isize)
                            << 32 as libc::c_int - 18 as libc::c_int)
                    ^ *W.offset((i + 8 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 3 as libc::c_int,
            )
            .wrapping_add(*W.offset((i + 8 as libc::c_int) as isize));
        *W.offset((i + 9 as libc::c_int + 16 as libc::c_int) as isize) = ((*W
            .offset((i + 9 as libc::c_int + 14 as libc::c_int) as isize)
            >> 17 as libc::c_int
            | *W.offset((i + 9 as libc::c_int + 14 as libc::c_int) as isize)
                << 32 as libc::c_int - 17 as libc::c_int)
            ^ (*W.offset((i + 9 as libc::c_int + 14 as libc::c_int) as isize)
                >> 19 as libc::c_int
                | *W.offset((i + 9 as libc::c_int + 14 as libc::c_int) as isize)
                    << 32 as libc::c_int - 19 as libc::c_int)
            ^ *W.offset((i + 9 as libc::c_int + 14 as libc::c_int) as isize) >> 10 as libc::c_int)
            .wrapping_add(*W.offset((i + 9 as libc::c_int + 9 as libc::c_int) as isize))
            .wrapping_add(
                (*W.offset((i + 9 as libc::c_int + 1 as libc::c_int) as isize) >> 7 as libc::c_int
                    | *W.offset((i + 9 as libc::c_int + 1 as libc::c_int) as isize)
                        << 32 as libc::c_int - 7 as libc::c_int)
                    ^ (*W.offset((i + 9 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 18 as libc::c_int
                        | *W.offset((i + 9 as libc::c_int + 1 as libc::c_int) as isize)
                            << 32 as libc::c_int - 18 as libc::c_int)
                    ^ *W.offset((i + 9 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 3 as libc::c_int,
            )
            .wrapping_add(*W.offset((i + 9 as libc::c_int) as isize));
        *W.offset((i + 10 as libc::c_int + 16 as libc::c_int) as isize) = ((*W
            .offset((i + 10 as libc::c_int + 14 as libc::c_int) as isize)
            >> 17 as libc::c_int
            | *W.offset((i + 10 as libc::c_int + 14 as libc::c_int) as isize)
                << 32 as libc::c_int - 17 as libc::c_int)
            ^ (*W.offset((i + 10 as libc::c_int + 14 as libc::c_int) as isize)
                >> 19 as libc::c_int
                | *W.offset((i + 10 as libc::c_int + 14 as libc::c_int) as isize)
                    << 32 as libc::c_int - 19 as libc::c_int)
            ^ *W.offset((i + 10 as libc::c_int + 14 as libc::c_int) as isize) >> 10 as libc::c_int)
            .wrapping_add(*W.offset((i + 10 as libc::c_int + 9 as libc::c_int) as isize))
            .wrapping_add(
                (*W.offset((i + 10 as libc::c_int + 1 as libc::c_int) as isize)
                    >> 7 as libc::c_int
                    | *W.offset((i + 10 as libc::c_int + 1 as libc::c_int) as isize)
                        << 32 as libc::c_int - 7 as libc::c_int)
                    ^ (*W.offset((i + 10 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 18 as libc::c_int
                        | *W.offset((i + 10 as libc::c_int + 1 as libc::c_int) as isize)
                            << 32 as libc::c_int - 18 as libc::c_int)
                    ^ *W.offset((i + 10 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 3 as libc::c_int,
            )
            .wrapping_add(*W.offset((i + 10 as libc::c_int) as isize));
        *W.offset((i + 11 as libc::c_int + 16 as libc::c_int) as isize) = ((*W
            .offset((i + 11 as libc::c_int + 14 as libc::c_int) as isize)
            >> 17 as libc::c_int
            | *W.offset((i + 11 as libc::c_int + 14 as libc::c_int) as isize)
                << 32 as libc::c_int - 17 as libc::c_int)
            ^ (*W.offset((i + 11 as libc::c_int + 14 as libc::c_int) as isize)
                >> 19 as libc::c_int
                | *W.offset((i + 11 as libc::c_int + 14 as libc::c_int) as isize)
                    << 32 as libc::c_int - 19 as libc::c_int)
            ^ *W.offset((i + 11 as libc::c_int + 14 as libc::c_int) as isize) >> 10 as libc::c_int)
            .wrapping_add(*W.offset((i + 11 as libc::c_int + 9 as libc::c_int) as isize))
            .wrapping_add(
                (*W.offset((i + 11 as libc::c_int + 1 as libc::c_int) as isize)
                    >> 7 as libc::c_int
                    | *W.offset((i + 11 as libc::c_int + 1 as libc::c_int) as isize)
                        << 32 as libc::c_int - 7 as libc::c_int)
                    ^ (*W.offset((i + 11 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 18 as libc::c_int
                        | *W.offset((i + 11 as libc::c_int + 1 as libc::c_int) as isize)
                            << 32 as libc::c_int - 18 as libc::c_int)
                    ^ *W.offset((i + 11 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 3 as libc::c_int,
            )
            .wrapping_add(*W.offset((i + 11 as libc::c_int) as isize));
        *W.offset((i + 12 as libc::c_int + 16 as libc::c_int) as isize) = ((*W
            .offset((i + 12 as libc::c_int + 14 as libc::c_int) as isize)
            >> 17 as libc::c_int
            | *W.offset((i + 12 as libc::c_int + 14 as libc::c_int) as isize)
                << 32 as libc::c_int - 17 as libc::c_int)
            ^ (*W.offset((i + 12 as libc::c_int + 14 as libc::c_int) as isize)
                >> 19 as libc::c_int
                | *W.offset((i + 12 as libc::c_int + 14 as libc::c_int) as isize)
                    << 32 as libc::c_int - 19 as libc::c_int)
            ^ *W.offset((i + 12 as libc::c_int + 14 as libc::c_int) as isize) >> 10 as libc::c_int)
            .wrapping_add(*W.offset((i + 12 as libc::c_int + 9 as libc::c_int) as isize))
            .wrapping_add(
                (*W.offset((i + 12 as libc::c_int + 1 as libc::c_int) as isize)
                    >> 7 as libc::c_int
                    | *W.offset((i + 12 as libc::c_int + 1 as libc::c_int) as isize)
                        << 32 as libc::c_int - 7 as libc::c_int)
                    ^ (*W.offset((i + 12 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 18 as libc::c_int
                        | *W.offset((i + 12 as libc::c_int + 1 as libc::c_int) as isize)
                            << 32 as libc::c_int - 18 as libc::c_int)
                    ^ *W.offset((i + 12 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 3 as libc::c_int,
            )
            .wrapping_add(*W.offset((i + 12 as libc::c_int) as isize));
        *W.offset((i + 13 as libc::c_int + 16 as libc::c_int) as isize) = ((*W
            .offset((i + 13 as libc::c_int + 14 as libc::c_int) as isize)
            >> 17 as libc::c_int
            | *W.offset((i + 13 as libc::c_int + 14 as libc::c_int) as isize)
                << 32 as libc::c_int - 17 as libc::c_int)
            ^ (*W.offset((i + 13 as libc::c_int + 14 as libc::c_int) as isize)
                >> 19 as libc::c_int
                | *W.offset((i + 13 as libc::c_int + 14 as libc::c_int) as isize)
                    << 32 as libc::c_int - 19 as libc::c_int)
            ^ *W.offset((i + 13 as libc::c_int + 14 as libc::c_int) as isize) >> 10 as libc::c_int)
            .wrapping_add(*W.offset((i + 13 as libc::c_int + 9 as libc::c_int) as isize))
            .wrapping_add(
                (*W.offset((i + 13 as libc::c_int + 1 as libc::c_int) as isize)
                    >> 7 as libc::c_int
                    | *W.offset((i + 13 as libc::c_int + 1 as libc::c_int) as isize)
                        << 32 as libc::c_int - 7 as libc::c_int)
                    ^ (*W.offset((i + 13 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 18 as libc::c_int
                        | *W.offset((i + 13 as libc::c_int + 1 as libc::c_int) as isize)
                            << 32 as libc::c_int - 18 as libc::c_int)
                    ^ *W.offset((i + 13 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 3 as libc::c_int,
            )
            .wrapping_add(*W.offset((i + 13 as libc::c_int) as isize));
        *W.offset((i + 14 as libc::c_int + 16 as libc::c_int) as isize) = ((*W
            .offset((i + 14 as libc::c_int + 14 as libc::c_int) as isize)
            >> 17 as libc::c_int
            | *W.offset((i + 14 as libc::c_int + 14 as libc::c_int) as isize)
                << 32 as libc::c_int - 17 as libc::c_int)
            ^ (*W.offset((i + 14 as libc::c_int + 14 as libc::c_int) as isize)
                >> 19 as libc::c_int
                | *W.offset((i + 14 as libc::c_int + 14 as libc::c_int) as isize)
                    << 32 as libc::c_int - 19 as libc::c_int)
            ^ *W.offset((i + 14 as libc::c_int + 14 as libc::c_int) as isize) >> 10 as libc::c_int)
            .wrapping_add(*W.offset((i + 14 as libc::c_int + 9 as libc::c_int) as isize))
            .wrapping_add(
                (*W.offset((i + 14 as libc::c_int + 1 as libc::c_int) as isize)
                    >> 7 as libc::c_int
                    | *W.offset((i + 14 as libc::c_int + 1 as libc::c_int) as isize)
                        << 32 as libc::c_int - 7 as libc::c_int)
                    ^ (*W.offset((i + 14 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 18 as libc::c_int
                        | *W.offset((i + 14 as libc::c_int + 1 as libc::c_int) as isize)
                            << 32 as libc::c_int - 18 as libc::c_int)
                    ^ *W.offset((i + 14 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 3 as libc::c_int,
            )
            .wrapping_add(*W.offset((i + 14 as libc::c_int) as isize));
        *W.offset((i + 15 as libc::c_int + 16 as libc::c_int) as isize) = ((*W
            .offset((i + 15 as libc::c_int + 14 as libc::c_int) as isize)
            >> 17 as libc::c_int
            | *W.offset((i + 15 as libc::c_int + 14 as libc::c_int) as isize)
                << 32 as libc::c_int - 17 as libc::c_int)
            ^ (*W.offset((i + 15 as libc::c_int + 14 as libc::c_int) as isize)
                >> 19 as libc::c_int
                | *W.offset((i + 15 as libc::c_int + 14 as libc::c_int) as isize)
                    << 32 as libc::c_int - 19 as libc::c_int)
            ^ *W.offset((i + 15 as libc::c_int + 14 as libc::c_int) as isize) >> 10 as libc::c_int)
            .wrapping_add(*W.offset((i + 15 as libc::c_int + 9 as libc::c_int) as isize))
            .wrapping_add(
                (*W.offset((i + 15 as libc::c_int + 1 as libc::c_int) as isize)
                    >> 7 as libc::c_int
                    | *W.offset((i + 15 as libc::c_int + 1 as libc::c_int) as isize)
                        << 32 as libc::c_int - 7 as libc::c_int)
                    ^ (*W.offset((i + 15 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 18 as libc::c_int
                        | *W.offset((i + 15 as libc::c_int + 1 as libc::c_int) as isize)
                            << 32 as libc::c_int - 18 as libc::c_int)
                    ^ *W.offset((i + 15 as libc::c_int + 1 as libc::c_int) as isize)
                        >> 3 as libc::c_int,
            )
            .wrapping_add(*W.offset((i + 15 as libc::c_int) as isize));
        i += 16 as libc::c_int;
    }
    let ref mut fresh48 = *state.offset(0 as libc::c_int as isize);
    *fresh48 = (*fresh48 as libc::c_uint).wrapping_add(*S.offset(0 as libc::c_int as isize))
        as uint32_t as uint32_t;
    let ref mut fresh49 = *state.offset(1 as libc::c_int as isize);
    *fresh49 = (*fresh49 as libc::c_uint).wrapping_add(*S.offset(1 as libc::c_int as isize))
        as uint32_t as uint32_t;
    let ref mut fresh50 = *state.offset(2 as libc::c_int as isize);
    *fresh50 = (*fresh50 as libc::c_uint).wrapping_add(*S.offset(2 as libc::c_int as isize))
        as uint32_t as uint32_t;
    let ref mut fresh51 = *state.offset(3 as libc::c_int as isize);
    *fresh51 = (*fresh51 as libc::c_uint).wrapping_add(*S.offset(3 as libc::c_int as isize))
        as uint32_t as uint32_t;
    let ref mut fresh52 = *state.offset(4 as libc::c_int as isize);
    *fresh52 = (*fresh52 as libc::c_uint).wrapping_add(*S.offset(4 as libc::c_int as isize))
        as uint32_t as uint32_t;
    let ref mut fresh53 = *state.offset(5 as libc::c_int as isize);
    *fresh53 = (*fresh53 as libc::c_uint).wrapping_add(*S.offset(5 as libc::c_int as isize))
        as uint32_t as uint32_t;
    let ref mut fresh54 = *state.offset(6 as libc::c_int as isize);
    *fresh54 = (*fresh54 as libc::c_uint).wrapping_add(*S.offset(6 as libc::c_int as isize))
        as uint32_t as uint32_t;
    let ref mut fresh55 = *state.offset(7 as libc::c_int as isize);
    *fresh55 = (*fresh55 as libc::c_uint).wrapping_add(*S.offset(7 as libc::c_int as isize))
        as uint32_t as uint32_t;
}

static mut PAD: [uint8_t; 64] = [
    0x80 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
];

unsafe extern "C" fn SHA256_Pad(mut ctx: *mut libcperciva_SHA256_CTX, mut tmp32: *mut uint32_t) {
    let mut r: size_t = 0;
    r = (*ctx).count >> 3 as libc::c_int & 0x3f as libc::c_int as libc::c_ulong;
    if r < 56 as libc::c_int as libc::c_ulong {
        memcpy(
            &mut *((*ctx).buf).as_mut_ptr().offset(r as isize) as *mut uint8_t as *mut libc::c_void,
            PAD.as_ptr() as *const libc::c_void,
            (56 as libc::c_int as libc::c_ulong).wrapping_sub(r),
        );
    } else {
        memcpy(
            &mut *((*ctx).buf).as_mut_ptr().offset(r as isize) as *mut uint8_t as *mut libc::c_void,
            PAD.as_ptr() as *const libc::c_void,
            (64 as libc::c_int as libc::c_ulong).wrapping_sub(r),
        );
        SHA256_Transform(
            ((*ctx).state).as_mut_ptr(),
            ((*ctx).buf).as_mut_ptr(),
            &mut *tmp32.offset(0 as libc::c_int as isize),
            &mut *tmp32.offset(64 as libc::c_int as isize),
        );
        memset(
            &mut *((*ctx).buf).as_mut_ptr().offset(0 as libc::c_int as isize) as *mut uint8_t
                as *mut libc::c_void,
            0 as libc::c_int,
            56 as libc::c_int as libc::c_ulong,
        );
    }
    libcperciva_be64enc(
        &mut *((*ctx).buf).as_mut_ptr().offset(56 as libc::c_int as isize) as *mut uint8_t
            as *mut libc::c_void,
        (*ctx).count,
    );
    SHA256_Transform(
        ((*ctx).state).as_mut_ptr(),
        ((*ctx).buf).as_mut_ptr(),
        &mut *tmp32.offset(0 as libc::c_int as isize),
        &mut *tmp32.offset(64 as libc::c_int as isize),
    );
}

static mut initial_state: [uint32_t; 8] = [
    0x6a09e667 as libc::c_int as uint32_t,
    0xbb67ae85 as libc::c_uint,
    0x3c6ef372 as libc::c_int as uint32_t,
    0xa54ff53a as libc::c_uint,
    0x510e527f as libc::c_int as uint32_t,
    0x9b05688c as libc::c_uint,
    0x1f83d9ab as libc::c_int as uint32_t,
    0x5be0cd19 as libc::c_int as uint32_t,
];

#[no_mangle]
pub unsafe extern "C" fn libcperciva_SHA256_Init(mut ctx: *mut libcperciva_SHA256_CTX) {
    (*ctx).count = 0 as libc::c_int as uint64_t;
    memcpy(
        ((*ctx).state).as_mut_ptr() as *mut libc::c_void,
        initial_state.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint32_t; 8]>() as libc::c_ulong,
    );
}

unsafe extern "C" fn _SHA256_Update(
    mut ctx: *mut libcperciva_SHA256_CTX,
    mut in_0: *const libc::c_void,
    mut len: size_t,
    mut tmp32: *mut uint32_t,
) {
    let mut r: uint32_t = 0;
    let mut src: *const uint8_t = in_0 as *const uint8_t;
    if len == 0 as libc::c_int as libc::c_ulong {
        return;
    }
    r = ((*ctx).count >> 3 as libc::c_int & 0x3f as libc::c_int as libc::c_ulong) as uint32_t;
    (*ctx).count = ((*ctx).count as libc::c_ulong).wrapping_add(len << 3 as libc::c_int) as uint64_t
        as uint64_t;
    if len < (64 as libc::c_int as libc::c_uint).wrapping_sub(r) as libc::c_ulong {
        memcpy(
            &mut *((*ctx).buf).as_mut_ptr().offset(r as isize) as *mut uint8_t as *mut libc::c_void,
            src as *const libc::c_void,
            len,
        );
        return;
    }
    memcpy(
        &mut *((*ctx).buf).as_mut_ptr().offset(r as isize) as *mut uint8_t as *mut libc::c_void,
        src as *const libc::c_void,
        (64 as libc::c_int as libc::c_uint).wrapping_sub(r) as libc::c_ulong,
    );
    SHA256_Transform(
        ((*ctx).state).as_mut_ptr(),
        ((*ctx).buf).as_mut_ptr(),
        &mut *tmp32.offset(0 as libc::c_int as isize),
        &mut *tmp32.offset(64 as libc::c_int as isize),
    );
    src = src.offset((64 as libc::c_int as libc::c_uint).wrapping_sub(r) as isize);
    len = (len as libc::c_ulong)
        .wrapping_sub((64 as libc::c_int as libc::c_uint).wrapping_sub(r) as libc::c_ulong)
        as size_t as size_t;
    while len >= 64 as libc::c_int as libc::c_ulong {
        SHA256_Transform(
            ((*ctx).state).as_mut_ptr(),
            src,
            &mut *tmp32.offset(0 as libc::c_int as isize),
            &mut *tmp32.offset(64 as libc::c_int as isize),
        );
        src = src.offset(64 as libc::c_int as isize);
        len = (len as libc::c_ulong).wrapping_sub(64 as libc::c_int as libc::c_ulong) as size_t
            as size_t;
    }
    memcpy(
        ((*ctx).buf).as_mut_ptr() as *mut libc::c_void,
        src as *const libc::c_void,
        len,
    );
}

#[no_mangle]
pub unsafe extern "C" fn libcperciva_SHA256_Update(
    mut ctx: *mut libcperciva_SHA256_CTX,
    mut in_0: *const libc::c_void,
    mut len: size_t,
) {
    let mut tmp32: [uint32_t; 72] = [0; 72];
    _SHA256_Update(ctx, in_0, len, tmp32.as_mut_ptr());
}

unsafe extern "C" fn _SHA256_Final(
    mut digest: *mut uint8_t,
    mut ctx: *mut libcperciva_SHA256_CTX,
    mut tmp32: *mut uint32_t,
) {
    SHA256_Pad(ctx, tmp32);
    be32enc_vect(
        digest,
        ((*ctx).state).as_mut_ptr(),
        4 as libc::c_int as size_t,
    );
}

#[no_mangle]
pub unsafe extern "C" fn libcperciva_SHA256_Final(
    mut digest: *mut uint8_t,
    mut ctx: *mut libcperciva_SHA256_CTX,
) {
    let mut tmp32: [uint32_t; 72] = [0; 72];
    _SHA256_Final(digest, ctx, tmp32.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn libcperciva_SHA256_Buf(
    mut in_0: *const libc::c_void,
    mut len: size_t,
    mut digest: *mut uint8_t,
) {
    let mut ctx: libcperciva_SHA256_CTX = libcperciva_SHA256_CTX {
        state: [0; 8],
        count: 0,
        buf: [0; 64],
    };
    let mut tmp32: [uint32_t; 72] = [0; 72];
    libcperciva_SHA256_Init(&mut ctx);
    _SHA256_Update(&mut ctx, in_0, len, tmp32.as_mut_ptr());
    _SHA256_Final(digest, &mut ctx, tmp32.as_mut_ptr());
}

unsafe extern "C" fn _HMAC_SHA256_Init(
    mut ctx: *mut libcperciva_HMAC_SHA256_CTX,
    mut _K: *const libc::c_void,
    mut Klen: size_t,
    mut tmp32: *mut uint32_t,
    mut pad: *mut uint8_t,
    mut khash: *mut uint8_t,
) {
    let mut K: *const uint8_t = _K as *const uint8_t;
    let mut i: size_t = 0;
    if Klen > 64 as libc::c_int as libc::c_ulong {
        libcperciva_SHA256_Init(&mut (*ctx).ictx);
        _SHA256_Update(&mut (*ctx).ictx, K as *const libc::c_void, Klen, tmp32);
        _SHA256_Final(khash, &mut (*ctx).ictx, tmp32);
        K = khash;
        Klen = 32 as libc::c_int as size_t;
    }
    libcperciva_SHA256_Init(&mut (*ctx).ictx);
    memset(
        pad as *mut libc::c_void,
        0x36 as libc::c_int,
        64 as libc::c_int as libc::c_ulong,
    );
    i = 0 as libc::c_int as size_t;
    while i < Klen {
        let ref mut fresh56 = *pad.offset(i as isize);
        *fresh56 = (*fresh56 as libc::c_int ^ *K.offset(i as isize) as libc::c_int) as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    _SHA256_Update(
        &mut (*ctx).ictx,
        pad as *const libc::c_void,
        64 as libc::c_int as size_t,
        tmp32,
    );
    libcperciva_SHA256_Init(&mut (*ctx).octx);
    memset(
        pad as *mut libc::c_void,
        0x5c as libc::c_int,
        64 as libc::c_int as libc::c_ulong,
    );
    i = 0 as libc::c_int as size_t;
    while i < Klen {
        let ref mut fresh57 = *pad.offset(i as isize);
        *fresh57 = (*fresh57 as libc::c_int ^ *K.offset(i as isize) as libc::c_int) as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    _SHA256_Update(
        &mut (*ctx).octx,
        pad as *const libc::c_void,
        64 as libc::c_int as size_t,
        tmp32,
    );
}

#[no_mangle]
pub unsafe extern "C" fn libcperciva_HMAC_SHA256_Init(
    mut ctx: *mut libcperciva_HMAC_SHA256_CTX,
    mut _K: *const libc::c_void,
    mut Klen: size_t,
) {
    let mut tmp32: [uint32_t; 72] = [0; 72];
    let mut pad: [uint8_t; 64] = [0; 64];
    let mut khash: [uint8_t; 32] = [0; 32];
    _HMAC_SHA256_Init(
        ctx,
        _K,
        Klen,
        tmp32.as_mut_ptr(),
        pad.as_mut_ptr(),
        khash.as_mut_ptr(),
    );
}

unsafe extern "C" fn _HMAC_SHA256_Update(
    mut ctx: *mut libcperciva_HMAC_SHA256_CTX,
    mut in_0: *const libc::c_void,
    mut len: size_t,
    mut tmp32: *mut uint32_t,
) {
    _SHA256_Update(&mut (*ctx).ictx, in_0, len, tmp32);
}

#[no_mangle]
pub unsafe extern "C" fn libcperciva_HMAC_SHA256_Update(
    mut ctx: *mut libcperciva_HMAC_SHA256_CTX,
    mut in_0: *const libc::c_void,
    mut len: size_t,
) {
    let mut tmp32: [uint32_t; 72] = [0; 72];
    _HMAC_SHA256_Update(ctx, in_0, len, tmp32.as_mut_ptr());
}

unsafe extern "C" fn _HMAC_SHA256_Final(
    mut digest: *mut uint8_t,
    mut ctx: *mut libcperciva_HMAC_SHA256_CTX,
    mut tmp32: *mut uint32_t,
    mut ihash: *mut uint8_t,
) {
    _SHA256_Final(ihash, &mut (*ctx).ictx, tmp32);
    _SHA256_Update(
        &mut (*ctx).octx,
        ihash as *const libc::c_void,
        32 as libc::c_int as size_t,
        tmp32,
    );
    _SHA256_Final(digest, &mut (*ctx).octx, tmp32);
}

#[no_mangle]
pub unsafe extern "C" fn libcperciva_HMAC_SHA256_Final(
    mut digest: *mut uint8_t,
    mut ctx: *mut libcperciva_HMAC_SHA256_CTX,
) {
    let mut tmp32: [uint32_t; 72] = [0; 72];
    let mut ihash: [uint8_t; 32] = [0; 32];
    _HMAC_SHA256_Final(digest, ctx, tmp32.as_mut_ptr(), ihash.as_mut_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn libcperciva_HMAC_SHA256_Buf(
    mut K: *const libc::c_void,
    mut Klen: size_t,
    mut in_0: *const libc::c_void,
    mut len: size_t,
    mut digest: *mut uint8_t,
) {
    let mut ctx: libcperciva_HMAC_SHA256_CTX = libcperciva_HMAC_SHA256_CTX {
        ictx: libcperciva_SHA256_CTX {
            state: [0; 8],
            count: 0,
            buf: [0; 64],
        },
        octx: libcperciva_SHA256_CTX {
            state: [0; 8],
            count: 0,
            buf: [0; 64],
        },
    };
    let mut tmp32: [uint32_t; 72] = [0; 72];
    let mut tmp8: [uint8_t; 96] = [0; 96];
    _HMAC_SHA256_Init(
        &mut ctx,
        K,
        Klen,
        tmp32.as_mut_ptr(),
        &mut *tmp8.as_mut_ptr().offset(0 as libc::c_int as isize),
        &mut *tmp8.as_mut_ptr().offset(64 as libc::c_int as isize),
    );
    _HMAC_SHA256_Update(&mut ctx, in_0, len, tmp32.as_mut_ptr());
    _HMAC_SHA256_Final(
        digest,
        &mut ctx,
        tmp32.as_mut_ptr(),
        &mut *tmp8.as_mut_ptr().offset(0 as libc::c_int as isize),
    );
}

unsafe extern "C" fn SHA256_Pad_Almost(
    mut ctx: *mut libcperciva_SHA256_CTX,
    mut len: *mut uint8_t,
    mut tmp32: *mut uint32_t,
) -> libc::c_int {
    let mut r: uint32_t = 0;
    r = ((*ctx).count >> 3 as libc::c_int & 0x3f as libc::c_int as libc::c_ulong) as uint32_t;
    if r >= 56 as libc::c_int as libc::c_uint {
        return -(1 as libc::c_int);
    }
    libcperciva_be64enc(len as *mut libc::c_void, (*ctx).count);
    _SHA256_Update(
        ctx,
        PAD.as_ptr() as *const libc::c_void,
        (56 as libc::c_int as libc::c_uint).wrapping_sub(r) as size_t,
        tmp32,
    );
    (*ctx).buf[63 as libc::c_int as usize] = *len.offset(7 as libc::c_int as isize);
    _SHA256_Update(
        ctx,
        len as *const libc::c_void,
        7 as libc::c_int as size_t,
        tmp32,
    );
    return 0 as libc::c_int;
}

#[no_mangle]
pub unsafe extern "C" fn PBKDF2_SHA256(
    mut passwd: *const uint8_t,
    mut passwdlen: size_t,
    mut salt: *const uint8_t,
    mut saltlen: size_t,
    mut c: uint64_t,
    mut buf: *mut uint8_t,
    mut dkLen: size_t,
) {
    let mut current_block: u64;
    let mut Phctx: libcperciva_HMAC_SHA256_CTX = libcperciva_HMAC_SHA256_CTX {
        ictx: libcperciva_SHA256_CTX {
            state: [0; 8],
            count: 0,
            buf: [0; 64],
        },
        octx: libcperciva_SHA256_CTX {
            state: [0; 8],
            count: 0,
            buf: [0; 64],
        },
    };
    let mut PShctx: libcperciva_HMAC_SHA256_CTX = libcperciva_HMAC_SHA256_CTX {
        ictx: libcperciva_SHA256_CTX {
            state: [0; 8],
            count: 0,
            buf: [0; 64],
        },
        octx: libcperciva_SHA256_CTX {
            state: [0; 8],
            count: 0,
            buf: [0; 64],
        },
    };
    let mut hctx: libcperciva_HMAC_SHA256_CTX = libcperciva_HMAC_SHA256_CTX {
        ictx: libcperciva_SHA256_CTX {
            state: [0; 8],
            count: 0,
            buf: [0; 64],
        },
        octx: libcperciva_SHA256_CTX {
            state: [0; 8],
            count: 0,
            buf: [0; 64],
        },
    };
    let mut tmp32: [uint32_t; 72] = [0; 72];
    let mut u: C2RustUnnamed = C2RustUnnamed { tmp8: [0; 96] };
    let mut i: size_t = 0;
    let mut ivec: [uint8_t; 4] = [0; 4];
    let mut U: [uint8_t; 32] = [0; 32];
    let mut T: [uint8_t; 32] = [0; 32];
    let mut j: uint64_t = 0;
    let mut k: libc::c_int = 0;
    let mut clen: size_t = 0;
    if dkLen
        <= (32 as libc::c_int as libc::c_ulong).wrapping_mul(4294967295 as libc::c_uint as size_t)
    {
    } else {
        __assert_fail(
            b"dkLen <= 32 * (size_t)(UINT32_MAX)\0" as *const u8 as *const libc::c_char,
            b"sha256.c\0" as *const u8 as *const libc::c_char,
            558 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 98],
                &[libc::c_char; 98],
            >(
                b"void PBKDF2_SHA256(const uint8_t *, size_t, const uint8_t *, size_t, uint64_t, uint8_t *, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    if dkLen
        <= (32 as libc::c_int as libc::c_ulong).wrapping_mul(4294967295 as libc::c_uint as size_t)
    {
    } else {
        __assert_fail(
            b"dkLen <= 32 * (size_t)(UINT32_MAX)\0" as *const u8
                as *const libc::c_char,
            b"sha256.c\0" as *const u8 as *const libc::c_char,
            558 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 98],
                &[libc::c_char; 98],
            >(
                b"void PBKDF2_SHA256(const uint8_t *, size_t, const uint8_t *, size_t, uint64_t, uint8_t *, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    if c == 1 as libc::c_int as libc::c_ulong
        && dkLen & 31 as libc::c_int as libc::c_ulong == 0 as libc::c_int as libc::c_ulong
        && saltlen & 63 as libc::c_int as libc::c_ulong <= 51 as libc::c_int as libc::c_ulong
    {
        let mut oldcount: uint32_t = 0;
        let mut ivecp: *mut uint8_t = 0 as *mut uint8_t;
        _HMAC_SHA256_Init(
            &mut hctx,
            passwd as *const libc::c_void,
            passwdlen,
            tmp32.as_mut_ptr(),
            &mut *(u.tmp8).as_mut_ptr().offset(0 as libc::c_int as isize),
            &mut *(u.tmp8).as_mut_ptr().offset(64 as libc::c_int as isize),
        );
        _HMAC_SHA256_Update(
            &mut hctx,
            salt as *const libc::c_void,
            saltlen,
            tmp32.as_mut_ptr(),
        );
        oldcount = (hctx.ictx.count & ((0x3f as libc::c_int) << 3 as libc::c_int) as libc::c_ulong)
            as uint32_t;
        _HMAC_SHA256_Update(
            &mut hctx,
            b"\0\0\0\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            4 as libc::c_int as size_t,
            tmp32.as_mut_ptr(),
        );
        if (hctx.ictx.count & ((0x3f as libc::c_int) << 3 as libc::c_int) as libc::c_ulong)
            < oldcount as libc::c_ulong
            || SHA256_Pad_Almost(&mut hctx.ictx, (u.tmp8).as_mut_ptr(), tmp32.as_mut_ptr()) != 0
        {
            current_block = 5148802568647841240;
        } else {
            ivecp = (hctx.ictx.buf)
                .as_mut_ptr()
                .offset((oldcount >> 3 as libc::c_int) as isize);
            hctx.octx.count = (hctx.octx.count as libc::c_ulong)
                .wrapping_add(((32 as libc::c_int) << 3 as libc::c_int) as libc::c_ulong)
                as uint64_t as uint64_t;
            SHA256_Pad_Almost(&mut hctx.octx, (u.tmp8).as_mut_ptr(), tmp32.as_mut_ptr());
            i = 0 as libc::c_int as size_t;
            while i.wrapping_mul(32 as libc::c_int as libc::c_ulong) < dkLen {
                libcperciva_be32enc(
                    ivecp as *mut libc::c_void,
                    i.wrapping_add(1 as libc::c_int as libc::c_ulong) as uint32_t,
                );
                memcpy(
                    (u.state).as_mut_ptr() as *mut libc::c_void,
                    (hctx.ictx.state).as_mut_ptr() as *const libc::c_void,
                    ::core::mem::size_of::<[uint32_t; 8]>() as libc::c_ulong,
                );
                SHA256_Transform(
                    (u.state).as_mut_ptr(),
                    (hctx.ictx.buf).as_mut_ptr(),
                    &mut *tmp32.as_mut_ptr().offset(0 as libc::c_int as isize),
                    &mut *tmp32.as_mut_ptr().offset(64 as libc::c_int as isize),
                );
                be32enc_vect(
                    (hctx.octx.buf).as_mut_ptr(),
                    (u.state).as_mut_ptr(),
                    4 as libc::c_int as size_t,
                );
                memcpy(
                    (u.state).as_mut_ptr() as *mut libc::c_void,
                    (hctx.octx.state).as_mut_ptr() as *const libc::c_void,
                    ::core::mem::size_of::<[uint32_t; 8]>() as libc::c_ulong,
                );
                SHA256_Transform(
                    (u.state).as_mut_ptr(),
                    (hctx.octx.buf).as_mut_ptr(),
                    &mut *tmp32.as_mut_ptr().offset(0 as libc::c_int as isize),
                    &mut *tmp32.as_mut_ptr().offset(64 as libc::c_int as isize),
                );
                be32enc_vect(
                    &mut *buf.offset(i.wrapping_mul(32 as libc::c_int as libc::c_ulong) as isize),
                    (u.state).as_mut_ptr(),
                    4 as libc::c_int as size_t,
                );
                i = i.wrapping_add(1);
                i;
            }
            current_block = 1847472278776910194;
        }
    } else {
        current_block = 5148802568647841240;
    }
    match current_block {
        5148802568647841240 => {
            _HMAC_SHA256_Init(
                &mut Phctx,
                passwd as *const libc::c_void,
                passwdlen,
                tmp32.as_mut_ptr(),
                &mut *(u.tmp8).as_mut_ptr().offset(0 as libc::c_int as isize),
                &mut *(u.tmp8).as_mut_ptr().offset(64 as libc::c_int as isize),
            );
            memcpy(
                &mut PShctx as *mut libcperciva_HMAC_SHA256_CTX as *mut libc::c_void,
                &mut Phctx as *mut libcperciva_HMAC_SHA256_CTX as *const libc::c_void,
                ::core::mem::size_of::<libcperciva_HMAC_SHA256_CTX>() as libc::c_ulong,
            );
            _HMAC_SHA256_Update(
                &mut PShctx,
                salt as *const libc::c_void,
                saltlen,
                tmp32.as_mut_ptr(),
            );
            i = 0 as libc::c_int as size_t;
            while i.wrapping_mul(32 as libc::c_int as libc::c_ulong) < dkLen {
                libcperciva_be32enc(
                    ivec.as_mut_ptr() as *mut libc::c_void,
                    i.wrapping_add(1 as libc::c_int as libc::c_ulong) as uint32_t,
                );
                memcpy(
                    &mut hctx as *mut libcperciva_HMAC_SHA256_CTX as *mut libc::c_void,
                    &mut PShctx as *mut libcperciva_HMAC_SHA256_CTX as *const libc::c_void,
                    ::core::mem::size_of::<libcperciva_HMAC_SHA256_CTX>() as libc::c_ulong,
                );
                _HMAC_SHA256_Update(
                    &mut hctx,
                    ivec.as_mut_ptr() as *const libc::c_void,
                    4 as libc::c_int as size_t,
                    tmp32.as_mut_ptr(),
                );
                _HMAC_SHA256_Final(
                    T.as_mut_ptr(),
                    &mut hctx,
                    tmp32.as_mut_ptr(),
                    (u.tmp8).as_mut_ptr(),
                );
                if c > 1 as libc::c_int as libc::c_ulong {
                    memcpy(
                        U.as_mut_ptr() as *mut libc::c_void,
                        T.as_mut_ptr() as *const libc::c_void,
                        32 as libc::c_int as libc::c_ulong,
                    );
                    j = 2 as libc::c_int as uint64_t;
                    while j <= c {
                        memcpy(
                            &mut hctx as *mut libcperciva_HMAC_SHA256_CTX as *mut libc::c_void,
                            &mut Phctx as *mut libcperciva_HMAC_SHA256_CTX as *const libc::c_void,
                            ::core::mem::size_of::<libcperciva_HMAC_SHA256_CTX>() as libc::c_ulong,
                        );
                        _HMAC_SHA256_Update(
                            &mut hctx,
                            U.as_mut_ptr() as *const libc::c_void,
                            32 as libc::c_int as size_t,
                            tmp32.as_mut_ptr(),
                        );
                        _HMAC_SHA256_Final(
                            U.as_mut_ptr(),
                            &mut hctx,
                            tmp32.as_mut_ptr(),
                            (u.tmp8).as_mut_ptr(),
                        );
                        k = 0 as libc::c_int;
                        while k < 32 as libc::c_int {
                            T[k as usize] = (T[k as usize] as libc::c_int
                                ^ U[k as usize] as libc::c_int)
                                as uint8_t;
                            k += 1;
                            k;
                        }
                        j = j.wrapping_add(1);
                        j;
                    }
                }
                clen = dkLen.wrapping_sub(i.wrapping_mul(32 as libc::c_int as libc::c_ulong));
                if clen > 32 as libc::c_int as libc::c_ulong {
                    clen = 32 as libc::c_int as size_t;
                }
                memcpy(
                    &mut *buf.offset(i.wrapping_mul(32 as libc::c_int as libc::c_ulong) as isize)
                        as *mut uint8_t as *mut libc::c_void,
                    T.as_mut_ptr() as *const libc::c_void,
                    clen,
                );
                i = i.wrapping_add(1);
                i;
            }
        }
        _ => {}
    };
}
