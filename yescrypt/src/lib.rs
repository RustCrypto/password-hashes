#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![warn(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::checked_conversions,
    clippy::implicit_saturating_sub,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    //missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]
// Temporary lint overrides while C code is being translated
#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    path_statements,
    unused_assignments,
    unused_mut
)]

mod common;
mod sha256;

use crate::sha256::{libcperciva_HMAC_SHA256_Buf, libcperciva_SHA256_Buf, PBKDF2_SHA256};
use libc::{free, malloc, memcpy, memset};

type uint8_t = libc::c_uchar;
type uint32_t = libc::c_uint;
type uint64_t = libc::c_ulong;
type size_t = libc::c_ulong;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct yescrypt_local_t {
    pub base: *mut libc::c_void,
    pub aligned: *mut libc::c_void,
    pub base_size: size_t,
    pub aligned_size: size_t,
}

pub type yescrypt_region_t = yescrypt_local_t;
pub type yescrypt_shared_t = yescrypt_region_t;
pub type yescrypt_flags_t = uint32_t;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct yescrypt_params_t {
    pub flags: yescrypt_flags_t,
    pub N: uint64_t,
    pub r: uint32_t,
    pub p: uint32_t,
    pub t: uint32_t,
    pub g: uint32_t,
    pub NROM: uint64_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union yescrypt_binary_t {
    pub uc: [libc::c_uchar; 32],
    pub u64_0: [uint64_t; 4],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct pwxform_ctx_t {
    pub S: *mut uint32_t,
    pub S0: *mut [uint32_t; 2],
    pub S1: *mut [uint32_t; 2],
    pub S2: *mut [uint32_t; 2],
    pub w: size_t,
}

#[inline]
unsafe fn libcperciva_le32dec(mut pp: *const libc::c_void) -> uint32_t {
    let mut p: *const uint8_t = pp as *const uint8_t;
    return (*p.offset(0 as libc::c_int as isize) as uint32_t)
        .wrapping_add((*p.offset(1 as libc::c_int as isize) as uint32_t) << 8 as libc::c_int)
        .wrapping_add((*p.offset(2 as libc::c_int as isize) as uint32_t) << 16 as libc::c_int)
        .wrapping_add((*p.offset(3 as libc::c_int as isize) as uint32_t) << 24 as libc::c_int);
}

#[inline]
unsafe fn libcperciva_le32enc(mut pp: *mut libc::c_void, mut x: uint32_t) {
    let mut p: *mut uint8_t = pp as *mut uint8_t;
    *p.offset(0 as libc::c_int as isize) = (x & 0xff as libc::c_int as libc::c_uint) as uint8_t;
    *p.offset(1 as libc::c_int as isize) =
        (x >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as uint8_t;
    *p.offset(2 as libc::c_int as isize) =
        (x >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as uint8_t;
    *p.offset(3 as libc::c_int as isize) =
        (x >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as uint8_t;
}

unsafe fn blkcpy(mut dst: *mut uint32_t, mut src: *const uint32_t, mut count: size_t) {
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

unsafe fn blkxor(mut dst: *mut uint32_t, mut src: *const uint32_t, mut count: size_t) {
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

unsafe fn salsa20(mut B: *mut uint32_t, mut rounds: uint32_t) {
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

unsafe fn blockmix_salsa8(mut B: *mut uint32_t, mut Y: *mut uint32_t, mut r: size_t) {
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

unsafe fn pwxform(mut B: *mut uint32_t, mut ctx: *mut pwxform_ctx_t) {
    let mut X: *mut [[uint32_t; 2]; 2] = B as *mut [[uint32_t; 2]; 2];
    let mut S0: *mut [uint32_t; 2] = (*ctx).S0;
    let mut S1: *mut [uint32_t; 2] = (*ctx).S1;
    let mut S2: *mut [uint32_t; 2] = (*ctx).S2;
    let mut w: size_t = (*ctx).w;
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    let mut k: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < 6 as libc::c_int as libc::c_ulong {
        j = 0 as libc::c_int as size_t;
        while j < 4 as libc::c_int as libc::c_ulong {
            let mut xl: uint32_t =
                (*X.offset(j as isize))[0 as libc::c_int as usize][0 as libc::c_int as usize];
            let mut xh: uint32_t =
                (*X.offset(j as isize))[0 as libc::c_int as usize][1 as libc::c_int as usize];
            let mut p0: *mut [uint32_t; 2] = 0 as *mut [uint32_t; 2];
            let mut p1: *mut [uint32_t; 2] = 0 as *mut [uint32_t; 2];
            p0 = S0.offset(
                ((xl & ((((1 as libc::c_int) << 8 as libc::c_int) - 1 as libc::c_int)
                    * 2 as libc::c_int
                    * 8 as libc::c_int) as libc::c_uint) as libc::c_ulong)
                    .wrapping_div(::core::mem::size_of::<[uint32_t; 2]>() as libc::c_ulong)
                    as isize,
            );
            p1 = S1.offset(
                ((xh & ((((1 as libc::c_int) << 8 as libc::c_int) - 1 as libc::c_int)
                    * 2 as libc::c_int
                    * 8 as libc::c_int) as libc::c_uint) as libc::c_ulong)
                    .wrapping_div(::core::mem::size_of::<[uint32_t; 2]>() as libc::c_ulong)
                    as isize,
            );
            k = 0 as libc::c_int as size_t;
            while k < 2 as libc::c_int as libc::c_ulong {
                let mut x: uint64_t = 0;
                let mut s0: uint64_t = 0;
                let mut s1: uint64_t = 0;
                s0 = (((*p0.offset(k as isize))[1 as libc::c_int as usize] as uint64_t)
                    << 32 as libc::c_int)
                    .wrapping_add(
                        (*p0.offset(k as isize))[0 as libc::c_int as usize] as libc::c_ulong,
                    );
                s1 = (((*p1.offset(k as isize))[1 as libc::c_int as usize] as uint64_t)
                    << 32 as libc::c_int)
                    .wrapping_add(
                        (*p1.offset(k as isize))[0 as libc::c_int as usize] as libc::c_ulong,
                    );
                xl = (*X.offset(j as isize))[k as usize][0 as libc::c_int as usize];
                xh = (*X.offset(j as isize))[k as usize][1 as libc::c_int as usize];
                x = (xh as uint64_t).wrapping_mul(xl as libc::c_ulong);
                x = (x as libc::c_ulong).wrapping_add(s0) as uint64_t as uint64_t;
                x ^= s1;
                (*X.offset(j as isize))[k as usize][0 as libc::c_int as usize] = x as uint32_t;
                (*X.offset(j as isize))[k as usize][1 as libc::c_int as usize] =
                    (x >> 32 as libc::c_int) as uint32_t;
                if i != 0 as libc::c_int as libc::c_ulong
                    && i != (6 as libc::c_int - 1 as libc::c_int) as libc::c_ulong
                {
                    (*S2.offset(w as isize))[0 as libc::c_int as usize] = x as uint32_t;
                    (*S2.offset(w as isize))[1 as libc::c_int as usize] =
                        (x >> 32 as libc::c_int) as uint32_t;
                    w = w.wrapping_add(1);
                    w;
                }
                k = k.wrapping_add(1);
                k;
            }
            j = j.wrapping_add(1);
            j;
        }
        i = i.wrapping_add(1);
        i;
    }
    (*ctx).S0 = S2;
    (*ctx).S1 = S0;
    (*ctx).S2 = S1;
    (*ctx).w = w
        & (((1 as libc::c_int) << 8 as libc::c_int) * 2 as libc::c_int - 1 as libc::c_int)
            as libc::c_ulong;
}

unsafe fn blockmix_pwxform(mut B: *mut uint32_t, mut ctx: *mut pwxform_ctx_t, mut r: size_t) {
    let mut X: [uint32_t; 16] = [0; 16];
    let mut r1: size_t = 0;
    let mut i: size_t = 0;
    r1 = (128 as libc::c_int as libc::c_ulong)
        .wrapping_mul(r)
        .wrapping_div((4 as libc::c_int * 2 as libc::c_int * 8 as libc::c_int) as libc::c_ulong);
    blkcpy(
        X.as_mut_ptr(),
        &mut *B.offset(
            r1.wrapping_sub(1 as libc::c_int as libc::c_ulong)
                .wrapping_mul(
                    ((4 as libc::c_int * 2 as libc::c_int * 8 as libc::c_int) as libc::c_ulong)
                        .wrapping_div(::core::mem::size_of::<uint32_t>() as libc::c_ulong),
                ) as isize,
        ),
        ((4 as libc::c_int * 2 as libc::c_int * 8 as libc::c_int) as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<uint32_t>() as libc::c_ulong),
    );
    i = 0 as libc::c_int as size_t;
    while i < r1 {
        if r1 > 1 as libc::c_int as libc::c_ulong {
            blkxor(
                X.as_mut_ptr(),
                &mut *B.offset(
                    i.wrapping_mul(
                        ((4 as libc::c_int * 2 as libc::c_int * 8 as libc::c_int) as libc::c_ulong)
                            .wrapping_div(::core::mem::size_of::<uint32_t>() as libc::c_ulong),
                    ) as isize,
                ),
                ((4 as libc::c_int * 2 as libc::c_int * 8 as libc::c_int) as libc::c_ulong)
                    .wrapping_div(::core::mem::size_of::<uint32_t>() as libc::c_ulong),
            );
        }
        pwxform(X.as_mut_ptr(), ctx);
        blkcpy(
            &mut *B.offset(
                i.wrapping_mul(
                    ((4 as libc::c_int * 2 as libc::c_int * 8 as libc::c_int) as libc::c_ulong)
                        .wrapping_div(::core::mem::size_of::<uint32_t>() as libc::c_ulong),
                ) as isize,
            ),
            X.as_mut_ptr(),
            ((4 as libc::c_int * 2 as libc::c_int * 8 as libc::c_int) as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<uint32_t>() as libc::c_ulong),
        );
        i = i.wrapping_add(1);
        i;
    }
    i = r1
        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        .wrapping_mul((4 as libc::c_int * 2 as libc::c_int * 8 as libc::c_int) as libc::c_ulong)
        .wrapping_div(64 as libc::c_int as libc::c_ulong);
    salsa20(
        &mut *B.offset(i.wrapping_mul(16 as libc::c_int as libc::c_ulong) as isize),
        2 as libc::c_int as uint32_t,
    );
    i = i.wrapping_add(1);
    i;
    while i < (2 as libc::c_int as libc::c_ulong).wrapping_mul(r) {
        blkxor(
            &mut *B.offset(i.wrapping_mul(16 as libc::c_int as libc::c_ulong) as isize),
            &mut *B.offset(
                i.wrapping_sub(1 as libc::c_int as libc::c_ulong)
                    .wrapping_mul(16 as libc::c_int as libc::c_ulong) as isize,
            ),
            16 as libc::c_int as size_t,
        );
        salsa20(
            &mut *B.offset(i.wrapping_mul(16 as libc::c_int as libc::c_ulong) as isize),
            2 as libc::c_int as uint32_t,
        );
        i = i.wrapping_add(1);
        i;
    }
}

unsafe fn integerify(mut B: *const uint32_t, mut r: size_t) -> uint64_t {
    let mut X: *const uint32_t = &*B.offset(
        (2 as libc::c_int as libc::c_ulong)
            .wrapping_mul(r)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_mul(16 as libc::c_int as libc::c_ulong) as isize,
    ) as *const uint32_t;
    return ((*X.offset(13 as libc::c_int as isize) as uint64_t) << 32 as libc::c_int)
        .wrapping_add(*X.offset(0 as libc::c_int as isize) as libc::c_ulong);
}

unsafe fn p2floor(mut x: uint64_t) -> uint64_t {
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

unsafe fn wrap(mut x: uint64_t, mut i: uint64_t) -> uint64_t {
    let mut n: uint64_t = p2floor(i);
    return (x & n.wrapping_sub(1 as libc::c_int as libc::c_ulong)).wrapping_add(i.wrapping_sub(n));
}

unsafe fn smix1(
    mut B: *mut uint32_t,
    mut r: size_t,
    mut N: uint64_t,
    mut flags: yescrypt_flags_t,
    mut V: *mut uint32_t,
    mut NROM: uint64_t,
    mut VROM: *const uint32_t,
    mut XY: *mut uint32_t,
    mut ctx: *mut pwxform_ctx_t,
) {
    let mut s: size_t = (32 as libc::c_int as libc::c_ulong).wrapping_mul(r);
    let mut X: *mut uint32_t = XY;
    let mut Y: *mut uint32_t = &mut *XY.offset(s as isize) as *mut uint32_t;
    let mut i: uint64_t = 0;
    let mut j: uint64_t = 0;
    let mut k: size_t = 0;
    k = 0 as libc::c_int as size_t;
    while k < (2 as libc::c_int as libc::c_ulong).wrapping_mul(r) {
        i = 0 as libc::c_int as uint64_t;
        while i < 16 as libc::c_int as libc::c_ulong {
            *X.offset(
                k.wrapping_mul(16 as libc::c_int as libc::c_ulong)
                    .wrapping_add(i) as isize,
            ) = libcperciva_le32dec(
                &mut *B.offset(
                    k.wrapping_mul(16 as libc::c_int as libc::c_ulong)
                        .wrapping_add(
                            i.wrapping_mul(5 as libc::c_int as libc::c_ulong)
                                .wrapping_rem(16 as libc::c_int as libc::c_ulong),
                        ) as isize,
                ) as *mut uint32_t as *const libc::c_void,
            );
            i = i.wrapping_add(1);
            i;
        }
        k = k.wrapping_add(1);
        k;
    }
    i = 0 as libc::c_int as uint64_t;
    while i < N {
        blkcpy(&mut *V.offset(i.wrapping_mul(s) as isize), X, s);
        if !VROM.is_null() && i == 0 as libc::c_int as libc::c_ulong {
            blkxor(
                X,
                &*VROM.offset(
                    NROM.wrapping_sub(1 as libc::c_int as libc::c_ulong)
                        .wrapping_mul(s) as isize,
                ),
                s,
            );
        } else if !VROM.is_null() && i & 1 as libc::c_int as libc::c_ulong != 0 {
            j = integerify(X, r) & NROM.wrapping_sub(1 as libc::c_int as libc::c_ulong);
            blkxor(X, &*VROM.offset(j.wrapping_mul(s) as isize), s);
        } else if flags & 0x2 as libc::c_int as libc::c_uint != 0
            && i > 1 as libc::c_int as libc::c_ulong
        {
            j = wrap(integerify(X, r), i);
            blkxor(X, &mut *V.offset(j.wrapping_mul(s) as isize), s);
        }
        if !ctx.is_null() {
            blockmix_pwxform(X, ctx, r);
        } else {
            blockmix_salsa8(X, Y, r);
        }
        i = i.wrapping_add(1);
        i;
    }
    k = 0 as libc::c_int as size_t;
    while k < (2 as libc::c_int as libc::c_ulong).wrapping_mul(r) {
        i = 0 as libc::c_int as uint64_t;
        while i < 16 as libc::c_int as libc::c_ulong {
            libcperciva_le32enc(
                &mut *B.offset(
                    k.wrapping_mul(16 as libc::c_int as libc::c_ulong)
                        .wrapping_add(
                            i.wrapping_mul(5 as libc::c_int as libc::c_ulong)
                                .wrapping_rem(16 as libc::c_int as libc::c_ulong),
                        ) as isize,
                ) as *mut uint32_t as *mut libc::c_void,
                *X.offset(
                    k.wrapping_mul(16 as libc::c_int as libc::c_ulong)
                        .wrapping_add(i) as isize,
                ),
            );
            i = i.wrapping_add(1);
            i;
        }
        k = k.wrapping_add(1);
        k;
    }
}

unsafe fn smix2(
    mut B: *mut uint32_t,
    mut r: size_t,
    mut N: uint64_t,
    mut Nloop: uint64_t,
    mut flags: yescrypt_flags_t,
    mut V: *mut uint32_t,
    mut NROM: uint64_t,
    mut VROM: *const uint32_t,
    mut XY: *mut uint32_t,
    mut ctx: *mut pwxform_ctx_t,
) {
    let mut s: size_t = (32 as libc::c_int as libc::c_ulong).wrapping_mul(r);
    let mut X: *mut uint32_t = XY;
    let mut Y: *mut uint32_t = &mut *XY.offset(s as isize) as *mut uint32_t;
    let mut i: uint64_t = 0;
    let mut j: uint64_t = 0;
    let mut k: size_t = 0;
    k = 0 as libc::c_int as size_t;
    while k < (2 as libc::c_int as libc::c_ulong).wrapping_mul(r) {
        i = 0 as libc::c_int as uint64_t;
        while i < 16 as libc::c_int as libc::c_ulong {
            *X.offset(
                k.wrapping_mul(16 as libc::c_int as libc::c_ulong)
                    .wrapping_add(i) as isize,
            ) = libcperciva_le32dec(
                &mut *B.offset(
                    k.wrapping_mul(16 as libc::c_int as libc::c_ulong)
                        .wrapping_add(
                            i.wrapping_mul(5 as libc::c_int as libc::c_ulong)
                                .wrapping_rem(16 as libc::c_int as libc::c_ulong),
                        ) as isize,
                ) as *mut uint32_t as *const libc::c_void,
            );
            i = i.wrapping_add(1);
            i;
        }
        k = k.wrapping_add(1);
        k;
    }
    i = 0 as libc::c_int as uint64_t;
    while i < Nloop {
        if !VROM.is_null() && i & 1 as libc::c_int as libc::c_ulong != 0 {
            j = integerify(X, r) & NROM.wrapping_sub(1 as libc::c_int as libc::c_ulong);
            blkxor(X, &*VROM.offset(j.wrapping_mul(s) as isize), s);
        } else {
            j = integerify(X, r) & N.wrapping_sub(1 as libc::c_int as libc::c_ulong);
            blkxor(X, &mut *V.offset(j.wrapping_mul(s) as isize), s);
            if flags & 0x2 as libc::c_int as libc::c_uint != 0 {
                blkcpy(&mut *V.offset(j.wrapping_mul(s) as isize), X, s);
            }
        }
        if !ctx.is_null() {
            blockmix_pwxform(X, ctx, r);
        } else {
            blockmix_salsa8(X, Y, r);
        }
        i = i.wrapping_add(1);
        i;
    }
    k = 0 as libc::c_int as size_t;
    while k < (2 as libc::c_int as libc::c_ulong).wrapping_mul(r) {
        i = 0 as libc::c_int as uint64_t;
        while i < 16 as libc::c_int as libc::c_ulong {
            libcperciva_le32enc(
                &mut *B.offset(
                    k.wrapping_mul(16 as libc::c_int as libc::c_ulong)
                        .wrapping_add(
                            i.wrapping_mul(5 as libc::c_int as libc::c_ulong)
                                .wrapping_rem(16 as libc::c_int as libc::c_ulong),
                        ) as isize,
                ) as *mut uint32_t as *mut libc::c_void,
                *X.offset(
                    k.wrapping_mul(16 as libc::c_int as libc::c_ulong)
                        .wrapping_add(i) as isize,
                ),
            );
            i = i.wrapping_add(1);
            i;
        }
        k = k.wrapping_add(1);
        k;
    }
}

unsafe fn smix(
    mut B: *mut uint32_t,
    mut r: size_t,
    mut N: uint64_t,
    mut p: uint32_t,
    mut t: uint32_t,
    mut flags: yescrypt_flags_t,
    mut V: *mut uint32_t,
    mut NROM: uint64_t,
    mut VROM: *const uint32_t,
    mut XY: *mut uint32_t,
    mut ctx: *mut pwxform_ctx_t,
    mut passwd: *mut uint8_t,
) {
    let mut s: size_t = (32 as libc::c_int as libc::c_ulong).wrapping_mul(r);
    let mut Nchunk: uint64_t = 0;
    let mut Nloop_all: uint64_t = 0;
    let mut Nloop_rw: uint64_t = 0;
    let mut Vchunk: uint64_t = 0;
    let mut i: uint32_t = 0;
    Nchunk = N.wrapping_div(p as libc::c_ulong);
    Nloop_all = Nchunk;
    if flags & 0x2 as libc::c_int as libc::c_uint != 0 {
        if t <= 1 as libc::c_int as libc::c_uint {
            if t != 0 {
                Nloop_all = (Nloop_all as libc::c_ulong)
                    .wrapping_mul(2 as libc::c_int as libc::c_ulong)
                    as uint64_t as uint64_t;
            }
            Nloop_all = Nloop_all
                .wrapping_add(2 as libc::c_int as libc::c_ulong)
                .wrapping_div(3 as libc::c_int as libc::c_ulong);
        } else {
            Nloop_all = (Nloop_all as libc::c_ulong)
                .wrapping_mul(t.wrapping_sub(1 as libc::c_int as libc::c_uint) as libc::c_ulong)
                as uint64_t as uint64_t;
        }
    } else if t != 0 {
        if t == 1 as libc::c_int as libc::c_uint {
            Nloop_all = (Nloop_all as libc::c_ulong).wrapping_add(
                Nloop_all
                    .wrapping_add(1 as libc::c_int as libc::c_ulong)
                    .wrapping_div(2 as libc::c_int as libc::c_ulong),
            ) as uint64_t as uint64_t;
        }
        Nloop_all =
            (Nloop_all as libc::c_ulong).wrapping_mul(t as libc::c_ulong) as uint64_t as uint64_t;
    }
    Nloop_rw = 0 as libc::c_int as uint64_t;
    if flags & 0x1000000 as libc::c_int as libc::c_uint != 0 {
        Nloop_rw = Nloop_all;
    } else if flags & 0x2 as libc::c_int as libc::c_uint != 0 {
        Nloop_rw = Nloop_all.wrapping_div(p as libc::c_ulong);
    }
    Nchunk &= !(1 as libc::c_int as uint64_t);
    Nloop_all = Nloop_all.wrapping_add(1);
    Nloop_all;
    Nloop_all &= !(1 as libc::c_int as uint64_t);
    Nloop_rw = Nloop_rw.wrapping_add(1);
    Nloop_rw;
    Nloop_rw &= !(1 as libc::c_int as uint64_t);
    i = 0 as libc::c_int as uint32_t;
    Vchunk = 0 as libc::c_int as uint64_t;
    while i < p {
        let mut Np: uint64_t = if i < p.wrapping_sub(1 as libc::c_int as libc::c_uint) {
            Nchunk
        } else {
            N.wrapping_sub(Vchunk)
        };
        let mut Bp: *mut uint32_t =
            &mut *B.offset((i as libc::c_ulong).wrapping_mul(s) as isize) as *mut uint32_t;
        let mut Vp: *mut uint32_t =
            &mut *V.offset(Vchunk.wrapping_mul(s) as isize) as *mut uint32_t;
        let mut ctx_i: *mut pwxform_ctx_t = 0 as *mut pwxform_ctx_t;
        if flags & 0x2 as libc::c_int as libc::c_uint != 0 {
            ctx_i = &mut *ctx.offset(i as isize) as *mut pwxform_ctx_t;
            smix1(
                Bp,
                1 as libc::c_int as size_t,
                (3 as libc::c_int
                    * ((1 as libc::c_int) << 8 as libc::c_int)
                    * 2 as libc::c_int
                    * 8 as libc::c_int
                    / 128 as libc::c_int) as uint64_t,
                0 as libc::c_int as yescrypt_flags_t,
                (*ctx_i).S,
                0 as libc::c_int as uint64_t,
                0 as *const uint32_t,
                XY,
                0 as *mut pwxform_ctx_t,
            );
            (*ctx_i).S2 = (*ctx_i).S as *mut [uint32_t; 2];
            (*ctx_i).S1 = ((*ctx_i).S2)
                .offset((((1 as libc::c_int) << 8 as libc::c_int) * 2 as libc::c_int) as isize);
            (*ctx_i).S0 = ((*ctx_i).S1)
                .offset((((1 as libc::c_int) << 8 as libc::c_int) * 2 as libc::c_int) as isize);
            (*ctx_i).w = 0 as libc::c_int as size_t;
            if i == 0 as libc::c_int as libc::c_uint {
                libcperciva_HMAC_SHA256_Buf(
                    Bp.offset(s.wrapping_sub(16 as libc::c_int as libc::c_ulong) as isize)
                        as *const libc::c_void,
                    64 as libc::c_int as size_t,
                    passwd as *const libc::c_void,
                    32 as libc::c_int as size_t,
                    passwd,
                );
            }
        }
        smix1(Bp, r, Np, flags, Vp, NROM, VROM, XY, ctx_i);
        smix2(
            Bp,
            r,
            p2floor(Np),
            Nloop_rw,
            flags,
            Vp,
            NROM,
            VROM,
            XY,
            ctx_i,
        );
        i = i.wrapping_add(1);
        i;
        Vchunk = (Vchunk as libc::c_ulong).wrapping_add(Nchunk) as uint64_t as uint64_t;
    }
    i = 0 as libc::c_int as uint32_t;
    while i < p {
        let mut Bp_0: *mut uint32_t =
            &mut *B.offset((i as libc::c_ulong).wrapping_mul(s) as isize) as *mut uint32_t;
        smix2(
            Bp_0,
            r,
            N,
            Nloop_all.wrapping_sub(Nloop_rw),
            flags & !(0x2 as libc::c_int) as libc::c_uint,
            V,
            NROM,
            VROM,
            XY,
            if flags & 0x2 as libc::c_int as libc::c_uint != 0 {
                &mut *ctx.offset(i as isize)
            } else {
                0 as *mut pwxform_ctx_t
            },
        );
        i = i.wrapping_add(1);
        i;
    }
}

unsafe fn yescrypt_kdf_body(
    mut shared: *const yescrypt_shared_t,
    mut local: *mut yescrypt_local_t,
    mut passwd: *const uint8_t,
    mut passwdlen: size_t,
    mut salt: *const uint8_t,
    mut saltlen: size_t,
    mut flags: yescrypt_flags_t,
    mut N: uint64_t,
    mut r: uint32_t,
    mut p: uint32_t,
    mut t: uint32_t,
    mut NROM: uint64_t,
    mut buf: *mut uint8_t,
    mut buflen: size_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut retval: libc::c_int = -(1 as libc::c_int);
    let mut VROM: *const uint32_t = 0 as *const uint32_t;
    let mut B_size: usize = 0;
    let mut V_size: usize = 0;
    let mut B: *mut uint32_t = 0 as *mut uint32_t;
    let mut V: *mut uint32_t = 0 as *mut uint32_t;
    let mut XY: *mut uint32_t = 0 as *mut uint32_t;
    let mut S: *mut uint32_t = 0 as *mut uint32_t;
    let mut pwxform_ctx: *mut pwxform_ctx_t = 0 as *mut pwxform_ctx_t;
    let mut sha256: [uint32_t; 8] = [0; 8];
    let mut dk: [uint8_t; 32] = [0; 32];
    let mut dkp: *mut uint8_t = buf;
    let mut i: uint32_t = 0;
    match flags & 0x3 as libc::c_int as libc::c_uint {
        0 => {
            if flags != 0 || t != 0 || NROM != 0 {
                current_block = 15162489974460950378;
            } else {
                current_block = 2868539653012386629;
            }
        }
        1 => {
            if flags != 1 as libc::c_int as libc::c_uint || NROM != 0 {
                current_block = 15162489974460950378;
            } else {
                current_block = 2868539653012386629;
            }
        }
        2 => {
            if flags
                != flags
                    & (0x3 as libc::c_int
                        | 0x3fc as libc::c_int
                        | 0x10000 as libc::c_int
                        | 0x1000000 as libc::c_int
                        | 0x8000000 as libc::c_int
                        | 0x10000000 as libc::c_int) as libc::c_uint
            {
                current_block = 15162489974460950378;
            } else if flags & 0x3fc as libc::c_int as libc::c_uint
                == (0x4 as libc::c_int
                    | 0x10 as libc::c_int
                    | 0x20 as libc::c_int
                    | 0x80 as libc::c_int) as libc::c_uint
            {
                current_block = 2868539653012386629;
            } else {
                current_block = 15162489974460950378;
            }
        }
        _ => {
            current_block = 15162489974460950378;
        }
    }
    match current_block {
        2868539653012386629 => {
            if !(buflen
                > ((1 as libc::c_int as uint64_t) << 32 as libc::c_int)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                    .wrapping_mul(32 as libc::c_int as libc::c_ulong))
            {
                if !((r as uint64_t).wrapping_mul(p as uint64_t)
                    >= ((1 as libc::c_int) << 30 as libc::c_int) as libc::c_ulong)
                {
                    if !(N & N.wrapping_sub(1 as libc::c_int as libc::c_ulong)
                        != 0 as libc::c_int as libc::c_ulong
                        || N <= 1 as libc::c_int as libc::c_ulong
                        || r < 1 as libc::c_int as libc::c_uint
                        || p < 1 as libc::c_int as libc::c_uint)
                    {
                        if !(r as libc::c_ulong
                            > (18446744073709551615 as libc::c_ulong)
                                .wrapping_div(128 as libc::c_int as libc::c_ulong)
                                .wrapping_div(p as libc::c_ulong)
                            || N > (18446744073709551615 as libc::c_ulong)
                                .wrapping_div(128 as libc::c_int as libc::c_ulong)
                                .wrapping_div(r as libc::c_ulong))
                        {
                            if !(N
                                > (18446744073709551615 as libc::c_ulong).wrapping_div(
                                    (t as uint64_t).wrapping_add(1 as libc::c_int as libc::c_ulong),
                                ))
                            {
                                if flags & 0x2 as libc::c_int as libc::c_uint != 0 {
                                    if N.wrapping_div(p as libc::c_ulong)
                                        <= 1 as libc::c_int as libc::c_ulong
                                        || r < ((4 as libc::c_int
                                            * 2 as libc::c_int
                                            * 8 as libc::c_int
                                            + 127 as libc::c_int)
                                            / 128 as libc::c_int)
                                            as libc::c_uint
                                        || p as libc::c_ulong
                                            > (18446744073709551615 as libc::c_ulong).wrapping_div(
                                                (3 as libc::c_int
                                                    * ((1 as libc::c_int) << 8 as libc::c_int)
                                                    * 2 as libc::c_int
                                                    * 8 as libc::c_int)
                                                    as libc::c_ulong,
                                            )
                                        || p as libc::c_ulong
                                            > (18446744073709551615 as libc::c_ulong).wrapping_div(
                                                ::core::mem::size_of::<pwxform_ctx_t>()
                                                    as libc::c_ulong,
                                            )
                                    {
                                        current_block = 15162489974460950378;
                                    } else {
                                        current_block = 6009453772311597924;
                                    }
                                } else {
                                    current_block = 6009453772311597924;
                                }
                                match current_block {
                                    15162489974460950378 => {}
                                    _ => {
                                        VROM = 0 as *const uint32_t;
                                        if !shared.is_null() {
                                            let mut expected_size: uint64_t = (128 as libc::c_int
                                                as size_t)
                                                .wrapping_mul(r as libc::c_ulong)
                                                .wrapping_mul(NROM);
                                            if NROM
                                                & NROM
                                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                                != 0 as libc::c_int as libc::c_ulong
                                                || NROM <= 1 as libc::c_int as libc::c_ulong
                                                || (*shared).aligned_size < expected_size
                                            {
                                                current_block = 15162489974460950378;
                                            } else {
                                                if flags & 0x1000000 as libc::c_int as libc::c_uint
                                                    == 0
                                                {
                                                    let mut tag: *mut uint32_t = ((*shared).aligned
                                                        as *mut uint8_t)
                                                        .offset(expected_size as isize)
                                                        .offset(-(48 as libc::c_int as isize))
                                                        as *mut uint32_t;
                                                    let mut tag1: uint64_t = ((*tag
                                                        .offset(1 as libc::c_int as isize)
                                                        as uint64_t)
                                                        << 32 as libc::c_int)
                                                        .wrapping_add(
                                                            *tag.offset(0 as libc::c_int as isize)
                                                                as libc::c_ulong,
                                                        );
                                                    let mut tag2: uint64_t = ((*tag
                                                        .offset(3 as libc::c_int as isize)
                                                        as uint64_t)
                                                        << 32 as libc::c_int)
                                                        .wrapping_add(
                                                            *tag.offset(2 as libc::c_int as isize)
                                                                as libc::c_ulong,
                                                        );
                                                    if tag1 as libc::c_ulonglong
                                                        != 0x7470797263736579 as libc::c_ulonglong
                                                        || tag2 as libc::c_ulonglong
                                                            != 0x687361684d4f522d
                                                                as libc::c_ulonglong
                                                    {
                                                        current_block = 15162489974460950378;
                                                    } else {
                                                        current_block = 13472856163611868459;
                                                    }
                                                } else {
                                                    current_block = 13472856163611868459;
                                                }
                                                match current_block {
                                                    15162489974460950378 => {}
                                                    _ => {
                                                        VROM = (*shared).aligned as *const uint32_t;
                                                        current_block = 14763689060501151050;
                                                    }
                                                }
                                            }
                                        } else if NROM != 0 {
                                            current_block = 15162489974460950378;
                                        } else {
                                            current_block = 14763689060501151050;
                                        }
                                        match current_block {
                                            15162489974460950378 => {}
                                            _ => {
                                                V_size = 128usize
                                                    .wrapping_mul(r as usize)
                                                    .wrapping_mul(N as usize);
                                                if flags & 0x1000000 as libc::c_int as libc::c_uint
                                                    != 0
                                                {
                                                    V = (*local).aligned as *mut uint32_t;
                                                    if (*local).aligned_size < V_size as u64 {
                                                        if !((*local).base).is_null()
                                                            || !((*local).aligned).is_null()
                                                            || (*local).base_size != 0
                                                            || (*local).aligned_size != 0
                                                        {
                                                            current_block = 15162489974460950378;
                                                        } else {
                                                            V = malloc(V_size) as *mut uint32_t;
                                                            if V.is_null() {
                                                                return -(1 as libc::c_int);
                                                            }
                                                            (*local).aligned =
                                                                V as *mut libc::c_void;
                                                            (*local).base = (*local).aligned;
                                                            (*local).aligned_size = V_size as u64;
                                                            (*local).base_size =
                                                                (*local).aligned_size;
                                                            current_block = 9853141518545631134;
                                                        }
                                                    } else {
                                                        current_block = 9853141518545631134;
                                                    }
                                                    match current_block {
                                                        15162489974460950378 => {}
                                                        _ => {
                                                            if flags
                                                                & 0x8000000 as libc::c_int
                                                                    as libc::c_uint
                                                                != 0
                                                            {
                                                                return -(2 as libc::c_int);
                                                            }
                                                            current_block = 7746103178988627676;
                                                        }
                                                    }
                                                } else {
                                                    V = malloc(V_size) as *mut uint32_t;
                                                    if V.is_null() {
                                                        return -(1 as libc::c_int);
                                                    }
                                                    current_block = 7746103178988627676;
                                                }
                                                match current_block {
                                                    15162489974460950378 => {}
                                                    _ => {
                                                        B_size = 128usize
                                                            .wrapping_mul(r as usize)
                                                            .wrapping_mul(p as usize);
                                                        B = malloc(B_size) as *mut uint32_t;
                                                        if !B.is_null() {
                                                            XY = malloc(
                                                                256usize.wrapping_mul(r as usize),
                                                            )
                                                                as *mut uint32_t;
                                                            if !XY.is_null() {
                                                                S = 0 as *mut uint32_t;
                                                                pwxform_ctx =
                                                                    0 as *mut pwxform_ctx_t;
                                                                if flags
                                                                    & 0x2 as libc::c_int
                                                                        as libc::c_uint
                                                                    != 0
                                                                {
                                                                    S = malloc(
                                                                        (3usize
                                                                            * ((1usize) << 8usize)
                                                                            * 2usize
                                                                            * 8usize)
                                                                            .wrapping_mul(
                                                                                p as usize,
                                                                            ),
                                                                    )
                                                                        as *mut uint32_t;
                                                                    if S.is_null() {
                                                                        current_block =
                                                                            4048828170348623652;
                                                                    } else {
                                                                        pwxform_ctx = malloc(
                                                                            core::mem::size_of::<
                                                                                pwxform_ctx_t,
                                                                            >(
                                                                            )
                                                                            .wrapping_mul(
                                                                                p as usize,
                                                                            ),
                                                                        )
                                                                            as *mut pwxform_ctx_t;
                                                                        if pwxform_ctx.is_null() {
                                                                            current_block =
                                                                                15241037615328978;
                                                                        } else {
                                                                            current_block = 12381812505308290051;
                                                                        }
                                                                    }
                                                                } else {
                                                                    current_block =
                                                                        12381812505308290051;
                                                                }
                                                                match current_block {
                                                                    12381812505308290051 => {
                                                                        if flags != 0 {
                                                                            libcperciva_HMAC_SHA256_Buf(
                                                                                b"yescrypt-prehash\0" as *const u8 as *const libc::c_char
                                                                                    as *const libc::c_void,
                                                                                (if flags & 0x10000000 as libc::c_int as libc::c_uint != 0 {
                                                                                    16 as libc::c_int
                                                                                } else {
                                                                                    8 as libc::c_int
                                                                                }) as size_t,
                                                                                passwd as *const libc::c_void,
                                                                                passwdlen,
                                                                                sha256.as_mut_ptr() as *mut uint8_t,
                                                                            );
                                                                            passwd = sha256
                                                                                .as_mut_ptr()
                                                                                as *mut uint8_t;
                                                                            passwdlen = ::core::mem::size_of::<[uint32_t; 8]>()
                                                                                as libc::c_ulong;
                                                                        }
                                                                        PBKDF2_SHA256(
                                                                            passwd,
                                                                            passwdlen,
                                                                            salt,
                                                                            saltlen,
                                                                            1 as libc::c_int
                                                                                as uint64_t,
                                                                            B as *mut uint8_t,
                                                                            B_size as u64,
                                                                        );
                                                                        if flags != 0 {
                                                                            blkcpy(
                                                                                sha256.as_mut_ptr(),
                                                                                B,
                                                                                (::core::mem::size_of::<[uint32_t; 8]>() as libc::c_ulong)
                                                                                    .wrapping_div(
                                                                                        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
                                                                                    ),
                                                                            );
                                                                        }
                                                                        if flags
                                                                            & 0x2 as libc::c_int
                                                                                as libc::c_uint
                                                                            != 0
                                                                        {
                                                                            i = 0 as libc::c_int
                                                                                as uint32_t;
                                                                            while i < p {
                                                                                let ref mut fresh5 =
                                                                                    (*pwxform_ctx
                                                                                        .offset(
                                                                                        i as isize,
                                                                                    ))
                                                                                    .S;
                                                                                *fresh5 = &mut *S
                                                                                    .offset(
                                                                                        (i as libc::c_ulong)
                                                                                            .wrapping_mul(
                                                                                                ((3 as libc::c_int
                                                                                                    * ((1 as libc::c_int) << 8 as libc::c_int)
                                                                                                    * 2 as libc::c_int * 8 as libc::c_int) as libc::c_ulong)
                                                                                                    .wrapping_div(
                                                                                                        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
                                                                                                    ),
                                                                                            ) as isize,
                                                                                    ) as *mut uint32_t;
                                                                                i = i.wrapping_add(
                                                                                    1,
                                                                                );
                                                                                i;
                                                                            }
                                                                            smix(
                                                                                B,
                                                                                r as size_t,
                                                                                N,
                                                                                p,
                                                                                t,
                                                                                flags,
                                                                                V,
                                                                                NROM,
                                                                                VROM,
                                                                                XY,
                                                                                pwxform_ctx,
                                                                                sha256.as_mut_ptr()
                                                                                    as *mut uint8_t,
                                                                            );
                                                                        } else {
                                                                            i = 0 as libc::c_int
                                                                                as uint32_t;
                                                                            while i < p {
                                                                                smix(
                                                                                    &mut *B
                                                                                        .offset(
                                                                                            (32 as libc::c_int as size_t)
                                                                                                .wrapping_mul(r as libc::c_ulong)
                                                                                                .wrapping_mul(i as libc::c_ulong) as isize,
                                                                                        ),
                                                                                    r as size_t,
                                                                                    N,
                                                                                    1 as libc::c_int as uint32_t,
                                                                                    t,
                                                                                    flags,
                                                                                    V,
                                                                                    NROM,
                                                                                    VROM,
                                                                                    XY,
                                                                                    0 as *mut pwxform_ctx_t,
                                                                                    0 as *mut uint8_t,
                                                                                );
                                                                                i = i.wrapping_add(
                                                                                    1,
                                                                                );
                                                                                i;
                                                                            }
                                                                        }
                                                                        dkp = buf;
                                                                        if flags != 0
                                                                            && buflen
                                                                            < ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong
                                                                        {
                                                                            PBKDF2_SHA256(
                                                                                passwd,
                                                                                passwdlen,
                                                                                B as *mut uint8_t,
                                                                                B_size as u64,
                                                                                1 as libc::c_int as uint64_t,
                                                                                dk.as_mut_ptr(),
                                                                                ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
                                                                            );
                                                                            dkp = dk.as_mut_ptr();
                                                                        }
                                                                        PBKDF2_SHA256(
                                                                            passwd,
                                                                            passwdlen,
                                                                            B as *mut uint8_t,
                                                                            B_size as u64,
                                                                            1 as libc::c_int
                                                                                as uint64_t,
                                                                            buf,
                                                                            buflen,
                                                                        );
                                                                        if flags != 0
                                                                            && flags
                                                                                & 0x10000000
                                                                                    as libc::c_int
                                                                                    as libc::c_uint
                                                                                == 0
                                                                        {
                                                                            libcperciva_HMAC_SHA256_Buf(
                                                                                dkp as *const libc::c_void,
                                                                                ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
                                                                                b"Client Key\0" as *const u8 as *const libc::c_char
                                                                                    as *const libc::c_void,
                                                                                10 as libc::c_int as size_t,
                                                                                sha256.as_mut_ptr() as *mut uint8_t,
                                                                            );
                                                                            let mut clen: size_t =
                                                                                buflen;
                                                                            if clen
                                                                                > ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong
                                                                            {
                                                                                clen = ::core::mem::size_of::<[uint8_t; 32]>()
                                                                                    as libc::c_ulong;
                                                                            }
                                                                            libcperciva_SHA256_Buf(
                                                                                sha256.as_mut_ptr() as *mut uint8_t as *const libc::c_void,
                                                                                ::core::mem::size_of::<[uint32_t; 8]>() as libc::c_ulong,
                                                                                dk.as_mut_ptr(),
                                                                            );
                                                                            memcpy(
                                                                                buf as *mut libc::c_void,
                                                                                dk.as_mut_ptr() as *const libc::c_void,
                                                                                clen as usize,
                                                                            );
                                                                        }
                                                                        retval = 0 as libc::c_int;
                                                                        free(pwxform_ctx as *mut libc::c_void);
                                                                        current_block =
                                                                            15241037615328978;
                                                                    }
                                                                    _ => {}
                                                                }
                                                                match current_block {
                                                                    15241037615328978 => {
                                                                        free(
                                                                            S as *mut libc::c_void,
                                                                        );
                                                                    }
                                                                    _ => {}
                                                                }
                                                                free(XY as *mut libc::c_void);
                                                            }
                                                            free(B as *mut libc::c_void);
                                                        }
                                                        if flags
                                                            & 0x1000000 as libc::c_int
                                                                as libc::c_uint
                                                            == 0
                                                        {
                                                            free(V as *mut libc::c_void);
                                                        }
                                                        return retval;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    return -(1 as libc::c_int);
}

#[no_mangle]
pub unsafe fn yescrypt_kdf(
    mut shared: *const yescrypt_shared_t,
    mut local: *mut yescrypt_local_t,
    mut passwd: *const uint8_t,
    mut passwdlen: size_t,
    mut salt: *const uint8_t,
    mut saltlen: size_t,
    mut params: *const yescrypt_params_t,
    mut buf: *mut uint8_t,
    mut buflen: size_t,
) -> libc::c_int {
    let mut flags: yescrypt_flags_t = (*params).flags;
    let mut N: uint64_t = (*params).N;
    let mut r: uint32_t = (*params).r;
    let mut p: uint32_t = (*params).p;
    let mut t: uint32_t = (*params).t;
    let mut g: uint32_t = (*params).g;
    let mut NROM: uint64_t = (*params).NROM;
    let mut dk: [uint8_t; 32] = [0; 32];
    if g != 0 {
        return -(1 as libc::c_int);
    }
    if flags & 0x2 as libc::c_int as libc::c_uint != 0
        && p >= 1 as libc::c_int as libc::c_uint
        && N.wrapping_div(p as libc::c_ulong) >= 0x100 as libc::c_int as libc::c_ulong
        && N.wrapping_div(p as libc::c_ulong)
            .wrapping_mul(r as libc::c_ulong)
            >= 0x20000 as libc::c_int as libc::c_ulong
    {
        let mut retval: libc::c_int = yescrypt_kdf_body(
            shared,
            local,
            passwd,
            passwdlen,
            salt,
            saltlen,
            flags | 0x10000000 as libc::c_int as libc::c_uint,
            N >> 6 as libc::c_int,
            r,
            p,
            0 as libc::c_int as uint32_t,
            NROM,
            dk.as_mut_ptr(),
            ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
        );
        if retval != 0 {
            return retval;
        }
        passwd = dk.as_mut_ptr();
        passwdlen = ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong;
    }
    return yescrypt_kdf_body(
        shared, local, passwd, passwdlen, salt, saltlen, flags, N, r, p, t, NROM, buf, buflen,
    );
}

#[no_mangle]
pub unsafe fn yescrypt_init_shared(
    mut shared: *mut yescrypt_shared_t,
    mut seed: *const uint8_t,
    mut seedlen: size_t,
    mut params: *const yescrypt_params_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut flags: yescrypt_flags_t = (*params).flags;
    let mut N: uint64_t = (*params).NROM;
    let mut r: uint32_t = (*params).r;
    let mut p: uint32_t = (*params).p;
    let mut t: uint32_t = (*params).t;
    let mut half1: yescrypt_shared_t = yescrypt_shared_t {
        base: 0 as *mut libc::c_void,
        aligned: 0 as *mut libc::c_void,
        base_size: 0,
        aligned_size: 0,
    };
    let mut half2: yescrypt_shared_t = yescrypt_shared_t {
        base: 0 as *mut libc::c_void,
        aligned: 0 as *mut libc::c_void,
        base_size: 0,
        aligned_size: 0,
    };
    let mut salt: [uint8_t; 32] = [0; 32];
    let mut tag: *mut uint32_t = 0 as *mut uint32_t;
    if (*params).flags & 0x2 as libc::c_int as libc::c_uint == 0
        || (*params).N != 0
        || (*params).g != 0
    {
        return -(1 as libc::c_int);
    }
    if flags & 0x10000 as libc::c_int as libc::c_uint != 0 {
        if ((*shared).aligned).is_null() || (*shared).aligned_size == 0 {
            return -(1 as libc::c_int);
        }
        tag = ((*shared).aligned as *mut uint8_t)
            .offset((*shared).aligned_size as isize)
            .offset(-(48 as libc::c_int as isize)) as *mut uint32_t;
        memset(tag as *mut libc::c_void, 0, 48);
        current_block = 2968425633554183086;
    } else {
        (*shared).aligned = 0 as *mut libc::c_void;
        (*shared).base = (*shared).aligned;
        (*shared).aligned_size = 0 as libc::c_int as size_t;
        (*shared).base_size = (*shared).aligned_size;
        if yescrypt_kdf_body(
            0 as *const yescrypt_shared_t,
            shared,
            0 as *const uint8_t,
            0 as libc::c_int as size_t,
            0 as *const uint8_t,
            0 as libc::c_int as size_t,
            flags
                | 0x1000000 as libc::c_int as libc::c_uint
                | 0x8000000 as libc::c_int as libc::c_uint,
            N,
            r,
            p,
            t,
            0 as libc::c_int as uint64_t,
            0 as *mut uint8_t,
            0 as libc::c_int as size_t,
        ) != -(2 as libc::c_int)
            || ((*shared).aligned).is_null()
        {
            current_block = 13608846184267058342;
        } else {
            current_block = 2968425633554183086;
        }
    }
    match current_block {
        2968425633554183086 => {
            half2 = *shared;
            half1 = half2;
            half1.aligned_size = (half1.aligned_size as libc::c_ulong)
                .wrapping_div(2 as libc::c_int as libc::c_ulong)
                as size_t as size_t;
            half2.aligned = (half2.aligned as *mut uint8_t).offset(half1.aligned_size as isize)
                as *mut libc::c_void;
            half2.aligned_size = half1.aligned_size;
            N = (N as libc::c_ulong).wrapping_div(2 as libc::c_int as libc::c_ulong) as uint64_t
                as uint64_t;
            if !(yescrypt_kdf_body(
                0 as *const yescrypt_shared_t,
                &mut half1,
                seed,
                seedlen,
                b"yescrypt-ROMhash\0" as *const u8 as *const libc::c_char as *const uint8_t,
                16 as libc::c_int as size_t,
                flags | 0x1000000 as libc::c_int as libc::c_uint,
                N,
                r,
                p,
                t,
                0 as libc::c_int as uint64_t,
                salt.as_mut_ptr(),
                ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
            ) != 0)
            {
                if !(yescrypt_kdf_body(
                    &mut half1,
                    &mut half2,
                    seed,
                    seedlen,
                    salt.as_mut_ptr(),
                    ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
                    flags | 0x1000000 as libc::c_int as libc::c_uint,
                    N,
                    r,
                    p,
                    t,
                    N,
                    salt.as_mut_ptr(),
                    ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
                ) != 0)
                {
                    if !(yescrypt_kdf_body(
                        &mut half2,
                        &mut half1,
                        seed,
                        seedlen,
                        salt.as_mut_ptr(),
                        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
                        flags | 0x1000000 as libc::c_int as libc::c_uint,
                        N,
                        r,
                        p,
                        t,
                        N,
                        salt.as_mut_ptr(),
                        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
                    ) != 0)
                    {
                        tag = ((*shared).aligned as *mut uint8_t)
                            .offset((*shared).aligned_size as isize)
                            .offset(-(48 as libc::c_int as isize))
                            as *mut uint32_t;
                        *tag.offset(0 as libc::c_int as isize) = (0x7470797263736579
                            as libc::c_ulonglong
                            & 0xffffffff as libc::c_uint as libc::c_ulonglong)
                            as uint32_t;
                        *tag.offset(1 as libc::c_int as isize) =
                            (0x7470797263736579 as libc::c_ulonglong >> 32 as libc::c_int)
                                as uint32_t;
                        *tag.offset(2 as libc::c_int as isize) = (0x687361684d4f522d
                            as libc::c_ulonglong
                            & 0xffffffff as libc::c_uint as libc::c_ulonglong)
                            as uint32_t;
                        *tag.offset(3 as libc::c_int as isize) =
                            (0x687361684d4f522d as libc::c_ulonglong >> 32 as libc::c_int)
                                as uint32_t;
                        *tag.offset(4 as libc::c_int as isize) =
                            libcperciva_le32dec(salt.as_mut_ptr() as *const libc::c_void);
                        *tag.offset(5 as libc::c_int as isize) = libcperciva_le32dec(
                            salt.as_mut_ptr().offset(4 as libc::c_int as isize)
                                as *const libc::c_void,
                        );
                        *tag.offset(6 as libc::c_int as isize) = libcperciva_le32dec(
                            salt.as_mut_ptr().offset(8 as libc::c_int as isize)
                                as *const libc::c_void,
                        );
                        *tag.offset(7 as libc::c_int as isize) = libcperciva_le32dec(
                            salt.as_mut_ptr().offset(12 as libc::c_int as isize)
                                as *const libc::c_void,
                        );
                        *tag.offset(8 as libc::c_int as isize) = libcperciva_le32dec(
                            salt.as_mut_ptr().offset(16 as libc::c_int as isize)
                                as *const libc::c_void,
                        );
                        *tag.offset(9 as libc::c_int as isize) = libcperciva_le32dec(
                            salt.as_mut_ptr().offset(20 as libc::c_int as isize)
                                as *const libc::c_void,
                        );
                        *tag.offset(10 as libc::c_int as isize) = libcperciva_le32dec(
                            salt.as_mut_ptr().offset(24 as libc::c_int as isize)
                                as *const libc::c_void,
                        );
                        *tag.offset(11 as libc::c_int as isize) = libcperciva_le32dec(
                            salt.as_mut_ptr().offset(28 as libc::c_int as isize)
                                as *const libc::c_void,
                        );
                        return 0 as libc::c_int;
                    }
                }
            }
        }
        _ => {}
    }
    if flags & 0x10000 as libc::c_int as libc::c_uint == 0 {
        free((*shared).base);
    }
    return -(1 as libc::c_int);
}

#[no_mangle]
pub unsafe fn yescrypt_digest_shared(mut shared: *mut yescrypt_shared_t) -> *mut yescrypt_binary_t {
    static mut digest: yescrypt_binary_t = yescrypt_binary_t { uc: [0; 32] };
    let mut tag: *mut uint32_t = 0 as *mut uint32_t;
    let mut tag1: uint64_t = 0;
    let mut tag2: uint64_t = 0;
    if (*shared).aligned_size < 48 as libc::c_int as libc::c_ulong {
        return 0 as *mut yescrypt_binary_t;
    }
    tag = ((*shared).aligned as *mut uint8_t)
        .offset((*shared).aligned_size as isize)
        .offset(-(48 as libc::c_int as isize)) as *mut uint32_t;
    tag1 = ((*tag.offset(1 as libc::c_int as isize) as uint64_t) << 32 as libc::c_int)
        .wrapping_add(*tag.offset(0 as libc::c_int as isize) as libc::c_ulong);
    tag2 = ((*tag.offset(3 as libc::c_int as isize) as uint64_t) << 32 as libc::c_int)
        .wrapping_add(*tag.offset(2 as libc::c_int as isize) as libc::c_ulong);
    if tag1 as libc::c_ulonglong != 0x7470797263736579 as libc::c_ulonglong
        || tag2 as libc::c_ulonglong != 0x687361684d4f522d as libc::c_ulonglong
    {
        return 0 as *mut yescrypt_binary_t;
    }
    libcperciva_le32enc(
        (digest.uc).as_mut_ptr() as *mut libc::c_void,
        *tag.offset(4 as libc::c_int as isize),
    );
    libcperciva_le32enc(
        (digest.uc).as_mut_ptr().offset(4 as libc::c_int as isize) as *mut libc::c_void,
        *tag.offset(5 as libc::c_int as isize),
    );
    libcperciva_le32enc(
        (digest.uc).as_mut_ptr().offset(8 as libc::c_int as isize) as *mut libc::c_void,
        *tag.offset(6 as libc::c_int as isize),
    );
    libcperciva_le32enc(
        (digest.uc).as_mut_ptr().offset(12 as libc::c_int as isize) as *mut libc::c_void,
        *tag.offset(7 as libc::c_int as isize),
    );
    libcperciva_le32enc(
        (digest.uc).as_mut_ptr().offset(16 as libc::c_int as isize) as *mut libc::c_void,
        *tag.offset(8 as libc::c_int as isize),
    );
    libcperciva_le32enc(
        (digest.uc).as_mut_ptr().offset(20 as libc::c_int as isize) as *mut libc::c_void,
        *tag.offset(9 as libc::c_int as isize),
    );
    libcperciva_le32enc(
        (digest.uc).as_mut_ptr().offset(24 as libc::c_int as isize) as *mut libc::c_void,
        *tag.offset(10 as libc::c_int as isize),
    );
    libcperciva_le32enc(
        (digest.uc).as_mut_ptr().offset(28 as libc::c_int as isize) as *mut libc::c_void,
        *tag.offset(11 as libc::c_int as isize),
    );

    #[allow(static_mut_refs)]
    return &mut digest;
}

#[no_mangle]
pub unsafe fn yescrypt_free_shared(mut shared: *mut yescrypt_shared_t) -> libc::c_int {
    free((*shared).base);
    (*shared).aligned = 0 as *mut libc::c_void;
    (*shared).base = (*shared).aligned;
    (*shared).aligned_size = 0 as libc::c_int as size_t;
    (*shared).base_size = (*shared).aligned_size;
    return 0 as libc::c_int;
}

#[no_mangle]
pub unsafe fn yescrypt_init_local(mut local: *mut yescrypt_local_t) -> libc::c_int {
    (*local).aligned = 0 as *mut libc::c_void;
    (*local).base = (*local).aligned;
    (*local).aligned_size = 0 as libc::c_int as size_t;
    (*local).base_size = (*local).aligned_size;
    return 0 as libc::c_int;
}

#[no_mangle]
pub unsafe fn yescrypt_free_local(_local: *mut yescrypt_local_t) -> libc::c_int {
    return 0 as libc::c_int;
}