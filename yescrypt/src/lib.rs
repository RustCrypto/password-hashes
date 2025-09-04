#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![warn(
    //clippy::cast_lossless,
    //clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    //clippy::cast_sign_loss,
    clippy::checked_conversions,
    clippy::implicit_saturating_sub,
    clippy::panic,
    clippy::panic_in_result_fn,
    //missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]
// Temporary lint overrides while C code is being translated
#![allow(
    clippy::cast_possible_wrap,
    clippy::collapsible_if,
    clippy::needless_return,
    clippy::nonminimal_bool,
    clippy::ptr_offset_with_cast,
    clippy::single_match,
    clippy::too_many_arguments,
    clippy::toplevel_ref_arg,
    clippy::unnecessary_mut_passed,
    clippy::unwrap_used,
    non_camel_case_types,
    non_snake_case,
    path_statements,
    unused_assignments,
    unused_mut,
    unsafe_op_in_unsafe_fn
)]

// Adapted from the yescrypt reference implementation available at:
// <https://github.com/openwall/yescrypt>
//
// Relicensed from the BSD-2-Clause license to Apache 2.0+MIT with permission:
// <https://github.com/openwall/yescrypt/issues/7>

extern crate alloc;

mod common;
mod salsa20;
mod sha256;

use crate::{
    common::{blkcpy, blkxor, integerify, le32dec, le32enc, p2floor, wrap},
    sha256::{HMAC_SHA256_Buf, PBKDF2_SHA256, SHA256_Buf},
};
use alloc::{vec, vec::Vec};
use core::{
    mem::{self, size_of},
    ptr,
};
use libc::{free, malloc, memcpy};

type uint8_t = libc::c_uchar;
type uint32_t = libc::c_uint;
type uint64_t = libc::c_ulong;
type size_t = usize;

#[derive(Copy, Clone)]
#[repr(C)]
struct Local {
    pub base: *mut libc::c_void,
    pub aligned: *mut libc::c_void,
    pub base_size: size_t,
    pub aligned_size: size_t,
}

type Region = Local;
type Shared = Region;
type Flags = uint32_t;

#[derive(Copy, Clone)]
#[repr(C)]
struct Params {
    pub flags: Flags,
    pub N: uint64_t,
    pub r: uint32_t,
    pub p: uint32_t,
    pub t: uint32_t,
    pub g: uint32_t,
    pub NROM: uint64_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
struct PwxformCtx {
    pub S: *mut uint32_t,
    pub S0: *mut [uint32_t; 2],
    pub S1: *mut [uint32_t; 2],
    pub S2: *mut [uint32_t; 2],
    pub w: size_t,
}

/// yescrypt Key Derivation Function (KDF)
pub fn yescrypt_kdf(
    passwd: &[u8],
    salt: &[u8],
    flags: u32,
    n: u64,
    r: u32,
    p: u32,
    t: u32,
    g: u32,
    dstlen: usize,
) -> Vec<u8> {
    let params = Params {
        flags,
        N: n,
        r,
        p,
        t,
        g,
        NROM: 0,
    };

    let mut local: Local = unsafe { mem::zeroed() };
    unsafe {
        yescrypt_init_local(&mut local);
    }

    let mut dst = vec![0u8; dstlen];

    unsafe {
        yescrypt_kdf_inner(
            ptr::null(),
            &mut local,
            passwd.as_ptr(),
            passwd.len(),
            salt.as_ptr(),
            salt.len(),
            &params,
            dst.as_mut_ptr(),
            dstlen,
        )
    };
    dst
}

unsafe fn yescrypt_kdf_inner(
    mut shared: *const Shared,
    mut local: *mut Local,
    mut passwd: *const uint8_t,
    mut passwdlen: size_t,
    mut salt: *const uint8_t,
    mut saltlen: size_t,
    mut params: *const Params,
    mut buf: *mut uint8_t,
    mut buflen: size_t,
) -> libc::c_int {
    let mut flags: Flags = (*params).flags;
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
            size_of::<[uint8_t; 32]>(),
        );
        if retval != 0 {
            return retval;
        }
        passwd = dk.as_mut_ptr();
        passwdlen = size_of::<[uint8_t; 32]>();
    }
    return yescrypt_kdf_body(
        shared, local, passwd, passwdlen, salt, saltlen, flags, N, r, p, t, NROM, buf, buflen,
    );
}

unsafe fn yescrypt_init_local(mut local: *mut Local) -> libc::c_int {
    (*local).aligned = ptr::null_mut();
    (*local).base = (*local).aligned;
    (*local).aligned_size = 0 as libc::c_int as size_t;
    (*local).base_size = (*local).aligned_size;
    return 0 as libc::c_int;
}

unsafe fn yescrypt_kdf_body(
    mut shared: *const Shared,
    mut local: *mut Local,
    mut passwd: *const uint8_t,
    mut passwdlen: size_t,
    mut salt: *const uint8_t,
    mut saltlen: size_t,
    mut flags: Flags,
    mut N: u64,
    mut r: uint32_t,
    mut p: uint32_t,
    mut t: uint32_t,
    mut NROM: u64,
    mut buf: *mut uint8_t,
    mut buflen: size_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut retval: libc::c_int = -(1 as libc::c_int);
    let mut VROM: *const uint32_t = ptr::null();
    let mut B_size: usize = 0;
    let mut V_size: usize = 0;
    let mut B: *mut uint32_t = ptr::null_mut();
    let mut V: *mut uint32_t = ptr::null_mut();
    let mut XY: *mut uint32_t = ptr::null_mut();
    let mut S: *mut uint32_t = ptr::null_mut();
    let mut pwxform_ctx: *mut PwxformCtx = ptr::null_mut();
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
            if !(buflen > (1usize << 32).wrapping_sub(1).wrapping_mul(32)) {
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
                                                size_of::<PwxformCtx>() as libc::c_ulong,
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
                                        VROM = ptr::null();
                                        if !shared.is_null() {
                                            let mut expected_size = (128usize)
                                                .wrapping_mul(r as usize)
                                                .wrapping_mul(NROM as usize);
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
                                                    if (*local).aligned_size < V_size {
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
                                                            (*local).aligned_size = V_size;
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
                                                                S = ptr::null_mut();
                                                                pwxform_ctx = ptr::null_mut();
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
                                                                            size_of::<PwxformCtx>()
                                                                                .wrapping_mul(
                                                                                    p as usize,
                                                                                ),
                                                                        )
                                                                            as *mut PwxformCtx;
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
                                                                            HMAC_SHA256_Buf(
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
                                                                            passwdlen = size_of::<
                                                                                [uint32_t; 8],
                                                                            >(
                                                                            );
                                                                        }
                                                                        PBKDF2_SHA256(
                                                                            passwd,
                                                                            passwdlen,
                                                                            salt,
                                                                            saltlen,
                                                                            1 as libc::c_int
                                                                                as uint64_t,
                                                                            B as *mut uint8_t,
                                                                            B_size,
                                                                        );
                                                                        if flags != 0 {
                                                                            blkcpy(
                                                                                sha256.as_mut_ptr(),
                                                                                B,
                                                                                (size_of::<
                                                                                    [uint32_t; 8],
                                                                                >(
                                                                                ))
                                                                                .wrapping_div(
                                                                                    size_of::<
                                                                                        uint32_t,
                                                                                    >(
                                                                                    ),
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
                                                                                                        size_of::<uint32_t>() as libc::c_ulong,
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
                                                                                        .add(
                                                                                            (32usize)
                                                                                                .wrapping_mul(r as usize)
                                                                                                .wrapping_mul(i as usize),
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
                                                                                    ptr::null_mut(),
                                                                                    ptr::null_mut(),
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
                                                                                < size_of::<
                                                                                    [uint8_t; 32],
                                                                                >(
                                                                                )
                                                                        {
                                                                            PBKDF2_SHA256(
                                                                                passwd,
                                                                                passwdlen,
                                                                                B as *mut uint8_t,
                                                                                B_size,
                                                                                1 as libc::c_int
                                                                                    as uint64_t,
                                                                                dk.as_mut_ptr(),
                                                                                size_of::<
                                                                                    [uint8_t; 32],
                                                                                >(
                                                                                ),
                                                                            );
                                                                            dkp = dk.as_mut_ptr();
                                                                        }
                                                                        PBKDF2_SHA256(
                                                                            passwd,
                                                                            passwdlen,
                                                                            B as *mut uint8_t,
                                                                            B_size,
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
                                                                            HMAC_SHA256_Buf(
                                                                                dkp as *const libc::c_void,
                                                                                size_of::<[uint8_t; 32]>() ,
                                                                                b"Client Key\0" as *const u8 as *const libc::c_char
                                                                                    as *const libc::c_void,
                                                                                10 as libc::c_int as size_t,
                                                                                sha256.as_mut_ptr() as *mut uint8_t,
                                                                            );
                                                                            let mut clen: size_t =
                                                                                buflen;
                                                                            if clen
                                                                                > size_of::<
                                                                                    [uint8_t; 32],
                                                                                >(
                                                                                )
                                                                            {
                                                                                clen = size_of::<
                                                                                    [uint8_t; 32],
                                                                                >(
                                                                                );
                                                                            }
                                                                            SHA256_Buf(
                                                                                sha256.as_mut_ptr() as *mut uint8_t as *const libc::c_void,
                                                                                size_of::<[uint32_t; 8]>(),
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

unsafe fn pwxform(mut B: *mut uint32_t, mut ctx: *mut PwxformCtx) {
    let mut X: *mut [[uint32_t; 2]; 2] = B as *mut [[uint32_t; 2]; 2];
    let mut S0: *mut [uint32_t; 2] = (*ctx).S0;
    let mut S1: *mut [uint32_t; 2] = (*ctx).S1;
    let mut S2: *mut [uint32_t; 2] = (*ctx).S2;
    let mut w: size_t = (*ctx).w;
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    let mut k: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < 6 {
        j = 0 as libc::c_int as size_t;
        while j < 4 {
            let mut xl: uint32_t =
                (*X.offset(j as isize))[0 as libc::c_int as usize][0 as libc::c_int as usize];
            let mut xh: uint32_t =
                (*X.offset(j as isize))[0 as libc::c_int as usize][1 as libc::c_int as usize];
            let mut p0: *mut [uint32_t; 2] = ptr::null_mut();
            let mut p1: *mut [uint32_t; 2] = ptr::null_mut();
            p0 = S0.offset(
                ((xl & ((((1 as libc::c_int) << 8 as libc::c_int) - 1 as libc::c_int)
                    * 2 as libc::c_int
                    * 8 as libc::c_int) as libc::c_uint) as libc::c_ulong)
                    .wrapping_div(size_of::<[uint32_t; 2]>() as libc::c_ulong)
                    as isize,
            );
            p1 = S1.offset(
                ((xh & ((((1 as libc::c_int) << 8 as libc::c_int) - 1 as libc::c_int)
                    * 2 as libc::c_int
                    * 8 as libc::c_int) as libc::c_uint) as libc::c_ulong)
                    .wrapping_div(size_of::<[uint32_t; 2]>() as libc::c_ulong)
                    as isize,
            );
            k = 0 as libc::c_int as size_t;
            while k < 2 {
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
                if i != 0usize && i != (6 - 1) {
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
    (*ctx).w = w & (((1usize) << 8usize) * 2usize - 1usize);
}

unsafe fn blockmix_pwxform(mut B: *mut uint32_t, mut ctx: *mut PwxformCtx, mut r: usize) {
    let mut X: [uint32_t; 16] = [0; 16];
    let mut r1: size_t = 0;
    let mut i: size_t = 0;
    r1 = (128usize).wrapping_mul(r).wrapping_div(4 * 2 * 8);
    blkcpy(
        X.as_mut_ptr(),
        &mut *B.offset(
            r1.wrapping_sub(1usize)
                .wrapping_mul((4usize * 2 * 8).wrapping_div(size_of::<uint32_t>()))
                as isize,
        ),
        (4usize * 2 * 8).wrapping_div(size_of::<uint32_t>()),
    );
    i = 0 as libc::c_int as size_t;
    while i < r1 {
        if r1 > 1 {
            blkxor(
                X.as_mut_ptr(),
                &mut *B.offset(
                    i.wrapping_mul((4usize * 2 * 8).wrapping_div(size_of::<uint32_t>())) as isize,
                ),
                (4usize * 2 * 8).wrapping_div(size_of::<uint32_t>()),
            );
        }
        pwxform(X.as_mut_ptr(), ctx);
        blkcpy(
            &mut *B.offset(
                i.wrapping_mul((4usize * 2 * 8).wrapping_div(size_of::<uint32_t>())) as isize,
            ),
            X.as_mut_ptr(),
            (4usize * 2 * 8).wrapping_div(size_of::<uint32_t>()),
        );
        i = i.wrapping_add(1);
        i;
    }
    i = r1.wrapping_sub(1).wrapping_mul(4 * 2 * 8).wrapping_div(64);
    salsa20::salsa20_2(&mut *B.add(i.wrapping_mul(16)));
    i = i.wrapping_add(1);
    i;
    while i < (2usize).wrapping_mul(r) {
        blkxor(
            &mut *B.offset(i.wrapping_mul(16usize) as isize),
            &mut *B.offset(i.wrapping_sub(1usize).wrapping_mul(16usize) as isize),
            16 as libc::c_int as size_t,
        );
        salsa20::salsa20_2(&mut *B.offset(i.wrapping_mul(16) as isize));
        i = i.wrapping_add(1);
        i;
    }
}

unsafe fn smix(
    mut B: *mut uint32_t,
    mut r: usize,
    mut N: u64,
    mut p: uint32_t,
    mut t: uint32_t,
    mut flags: Flags,
    mut V: *mut uint32_t,
    mut NROM: u64,
    mut VROM: *const uint32_t,
    mut XY: *mut uint32_t,
    mut ctx: *mut PwxformCtx,
    mut passwd: *mut uint8_t,
) {
    let mut s: size_t = (32 * r) as size_t;
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
            &mut *B.offset((i as usize).wrapping_mul(s) as isize) as *mut uint32_t;
        let mut Vp: *mut uint32_t =
            &mut *V.offset((Vchunk as usize).wrapping_mul(s) as isize) as *mut uint32_t;
        let mut ctx_i: *mut PwxformCtx = ptr::null_mut();
        if flags & 0x2 as libc::c_int as libc::c_uint != 0 {
            ctx_i = &mut *ctx.offset(i as isize) as *mut PwxformCtx;
            smix1(
                Bp,
                1 as libc::c_int as size_t,
                (3 as libc::c_int
                    * ((1 as libc::c_int) << 8 as libc::c_int)
                    * 2 as libc::c_int
                    * 8 as libc::c_int
                    / 128 as libc::c_int) as uint64_t,
                0 as libc::c_int as Flags,
                (*ctx_i).S,
                0 as libc::c_int as uint64_t,
                ptr::null(),
                XY,
                ptr::null_mut(),
            );
            (*ctx_i).S2 = (*ctx_i).S as *mut [uint32_t; 2];
            (*ctx_i).S1 = ((*ctx_i).S2)
                .offset((((1 as libc::c_int) << 8 as libc::c_int) * 2 as libc::c_int) as isize);
            (*ctx_i).S0 = ((*ctx_i).S1)
                .offset((((1 as libc::c_int) << 8 as libc::c_int) * 2 as libc::c_int) as isize);
            (*ctx_i).w = 0 as libc::c_int as size_t;
            if i == 0 as libc::c_int as libc::c_uint {
                HMAC_SHA256_Buf(
                    Bp.offset(s.wrapping_sub(16) as isize) as *const libc::c_void,
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
            &mut *B.offset((i as usize).wrapping_mul(s) as isize) as *mut uint32_t;
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
                ptr::null_mut()
            },
        );
        i = i.wrapping_add(1);
        i;
    }
}

unsafe fn smix1(
    mut B: *mut uint32_t,
    mut r: usize,
    mut N: uint64_t,
    mut flags: Flags,
    mut V: *mut uint32_t,
    mut NROM: uint64_t,
    mut VROM: *const uint32_t,
    mut XY: *mut uint32_t,
    mut ctx: *mut PwxformCtx,
) {
    let mut s: size_t = (32usize).wrapping_mul(r);
    let mut X: *mut uint32_t = XY;
    let mut Y: *mut uint32_t = &mut *XY.offset(s as isize) as *mut uint32_t;
    let mut i: usize = 0;
    let mut j: uint64_t = 0;
    let mut k: size_t = 0;
    k = 0 as libc::c_int as size_t;
    while k < (2usize).wrapping_mul(r) {
        i = 0;
        while i < 16usize {
            *X.offset(k.wrapping_mul(16usize).wrapping_add(i) as isize) = le32dec(
                &mut *B.offset(
                    k.wrapping_mul(16usize)
                        .wrapping_add(i.wrapping_mul(5usize).wrapping_rem(16usize))
                        as isize,
                ) as *mut uint32_t as *const libc::c_void,
            );
            i = i.wrapping_add(1);
            i;
        }
        k = k.wrapping_add(1);
        k;
    }
    let mut i = 0;
    while i < N {
        blkcpy(
            &mut *V.offset(usize::try_from(i).unwrap().wrapping_mul(s) as isize),
            X,
            s,
        );
        if !VROM.is_null() && i == 0 as libc::c_int as libc::c_ulong {
            blkxor(
                X,
                &*VROM.offset(
                    usize::try_from(NROM)
                        .unwrap()
                        .wrapping_sub(1)
                        .wrapping_mul(s) as isize,
                ),
                s,
            );
        } else if !VROM.is_null() && i & 1 as libc::c_int as libc::c_ulong != 0 {
            j = integerify(X, r) & NROM.wrapping_sub(1);
            blkxor(
                X,
                &*VROM.offset(usize::try_from(j).unwrap().wrapping_mul(s) as isize),
                s,
            );
        } else if flags & 0x2 as libc::c_int as libc::c_uint != 0
            && i > 1 as libc::c_int as libc::c_ulong
        {
            j = wrap(integerify(X, r), i);
            blkxor(
                X,
                &mut *V.offset(usize::try_from(j).unwrap().wrapping_mul(s) as isize),
                s,
            );
        }
        if !ctx.is_null() {
            blockmix_pwxform(X, ctx, r);
        } else {
            salsa20::blockmix_salsa8(X, Y, r);
        }
        i = i.wrapping_add(1);
        i;
    }
    k = 0 as libc::c_int as size_t;
    while k < (2usize).wrapping_mul(r) {
        let mut i = 0;
        while i < 16usize {
            le32enc(
                &mut *B.offset(
                    k.wrapping_mul(16usize)
                        .wrapping_add(i.wrapping_mul(5usize).wrapping_rem(16usize))
                        as isize,
                ) as *mut uint32_t as *mut libc::c_void,
                *X.offset(k.wrapping_mul(16usize).wrapping_add(i) as isize),
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
    mut r: usize,
    mut N: u64,
    mut Nloop: u64,
    mut flags: Flags,
    mut V: *mut uint32_t,
    mut NROM: u64,
    mut VROM: *const uint32_t,
    mut XY: *mut uint32_t,
    mut ctx: *mut PwxformCtx,
) {
    let mut s: size_t = (32usize).wrapping_mul(r);
    let mut X: *mut uint32_t = XY;
    let mut Y: *mut uint32_t = &mut *XY.offset(s as isize) as *mut uint32_t;
    // let mut i: uint64_t = 0;
    let mut j: uint64_t = 0;
    let mut k: size_t = 0;
    k = 0 as libc::c_int as size_t;
    while k < (2usize).wrapping_mul(r) {
        let mut i = 0;
        while i < 16usize {
            *X.offset(k.wrapping_mul(16usize).wrapping_add(i) as isize) = le32dec(
                &mut *B.offset(
                    k.wrapping_mul(16usize)
                        .wrapping_add(i.wrapping_mul(5usize).wrapping_rem(16usize))
                        as isize,
                ) as *mut uint32_t as *const libc::c_void,
            );
            i = i.wrapping_add(1);
            i;
        }
        k = k.wrapping_add(1);
        k;
    }
    let mut i = 0;
    while i < Nloop {
        if !VROM.is_null() && i & 1 != 0 {
            j = integerify(X, r) & NROM.wrapping_sub(1);
            blkxor(
                X,
                &*VROM.offset(usize::try_from(j).unwrap().wrapping_mul(s) as isize),
                s,
            );
        } else {
            j = integerify(X, r) & N.wrapping_sub(1);
            blkxor(
                X,
                &mut *V.offset(usize::try_from(j).unwrap().wrapping_mul(s) as isize),
                s,
            );
            if flags & 0x2 as libc::c_int as libc::c_uint != 0 {
                blkcpy(
                    &mut *V.offset(usize::try_from(j).unwrap().wrapping_mul(s) as isize),
                    X,
                    s,
                );
            }
        }
        if !ctx.is_null() {
            blockmix_pwxform(X, ctx, r);
        } else {
            salsa20::blockmix_salsa8(X, Y, r);
        }
        i = i.wrapping_add(1);
        i;
    }
    k = 0 as libc::c_int as size_t;
    while k < (2usize).wrapping_mul(r) {
        let mut i = 0;
        while i < 16usize {
            le32enc(
                &mut *B.offset(
                    k.wrapping_mul(16)
                        .wrapping_add(i.wrapping_mul(5).wrapping_rem(16))
                        as isize,
                ) as *mut uint32_t as *mut libc::c_void,
                *X.offset(k.wrapping_mul(16).wrapping_add(i) as isize),
            );
            i = i.wrapping_add(1);
            i;
        }
        k = k.wrapping_add(1);
        k;
    }
}
