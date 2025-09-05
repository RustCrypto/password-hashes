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
    clippy::too_many_arguments,
    clippy::toplevel_ref_arg,
    clippy::unwrap_used,
    unsafe_op_in_unsafe_fn
)]

// Adapted from the yescrypt reference implementation available at:
// <https://github.com/openwall/yescrypt>
//
// Relicensed from the BSD-2-Clause license to Apache 2.0+MIT with permission:
// <https://github.com/openwall/yescrypt/issues/7>

extern crate alloc;

mod common;
mod error;
mod params;
mod pwxform;
mod salsa20;
mod sha256;
mod smix;

pub use crate::{
    error::{Error, Result},
    params::{Flags, Params},
};

use crate::{
    pwxform::PwxformCtx,
    sha256::{HMAC_SHA256_Buf, PBKDF2_SHA256, SHA256_Buf},
};
use alloc::{boxed::Box, vec, vec::Vec};
use core::ptr;
use libc::{c_void, free, malloc, memcpy};

#[derive(Clone)]
#[repr(C)]
struct Local {
    pub aligned: Box<[u32]>,
}

/// yescrypt Key Derivation Function (KDF)
pub fn yescrypt_kdf(passwd: &[u8], salt: &[u8], params: &Params, out: &mut [u8]) -> Result<()> {
    let mut local = Local {
        aligned: Vec::new().into_boxed_slice(),
    };

    if params.g != 0 {
        return Err(Error(-1));
    }

    if params.flags.contains(Flags::RW)
        && params.p >= 1
        && (params.n / params.p as u64) >= 0x100
        && params.n / (params.p as u64) / (params.r as u64) >= 0x20000
    {
        return Err(Error(-1));
    }

    unsafe {
        yescrypt_kdf_body(
            &mut local,
            passwd,
            salt,
            params.flags,
            params.n,
            params.r,
            params.p,
            params.t,
            params.nrom,
            out,
        )
    }
}

unsafe fn yescrypt_kdf_body(
    local: &mut Local,
    passwd: &[u8],
    salt: &[u8],
    flags: Flags,
    n: u64,
    r: u32,
    p: u32,
    t: u32,
    nrom: u64,
    out: &mut [u8],
) -> Result<()> {
    let mut passwdlen: usize = passwd.len();
    let mut passwd = passwd.as_ptr();

    let mut sha256 = [0u32; 8];
    let mut dk = [0u8; 32];

    match flags.bits() & Flags::MODE_MASK.bits() {
        0 => {
            if !flags.is_empty() || t != 0 || nrom != 0 {
                return Err(Error(-1));
            }
        }
        1 => {
            if flags != Flags::WORM || nrom != 0 {
                return Err(Error(-1));
            }
        }
        2 => {
            if flags
                != flags
                    & (Flags::MODE_MASK
                        | Flags::RW_FLAVOR_MASK
                        | Flags::SHARED_PREALLOCATED
                        | Flags::INIT_SHARED
                        | Flags::ALLOC_ONLY
                        | Flags::PREHASH)
            {
                return Err(Error(-1));
            }

            if (flags & Flags::RW_FLAVOR_MASK)
                != (Flags::ROUNDS_6 | Flags::GATHER_4 | Flags::SIMPLE_2 | Flags::SBOX_12K)
            {
                return Err(Error(-1));
            }
        }
        _ => {
            return Err(Error(-1));
        }
    }
    if !((out.len() <= ((1 << 32) - 1) * 32)
        && ((r as u64) * (p as u64) < (1 << 30) as u64)
        && !(n & (n - 1) != 0 || n <= 1 || r < 1 || p < 1)
        && !(r as u64 > u64::MAX / 128 / (p as u64) || n > u64::MAX / 128 / (r as u64))
        && (n <= u64::MAX / ((t as u64) + 1)))
    {
        return Err(Error(-1));
    }

    if flags.contains(Flags::RW)
        && (n / (p as u64) <= 1
            || r < ((4 * 2 * 8 + 127) / 128) as u32
            || p as u64 > u64::MAX / (3 * (1 << 8) * 2 * 8)
            || p as u64 > u64::MAX / (size_of::<PwxformCtx>() as u64))
    {
        return Err(Error(-1));
    }

    if nrom != 0 {
        return Err(Error(-1));
    }

    let mut v_owned: Box<[u32]>;
    let v_size = 32 * (r as usize) * (n as usize);
    let v = if flags.contains(Flags::INIT_SHARED) {
        if local.aligned.len() < v_size {
            // why can't we just reallocate here?
            if !local.aligned.is_empty() {
                return Err(Error(-1));
            }

            local.aligned = vec![0; v_size].into_boxed_slice();
        }
        if flags.contains(Flags::ALLOC_ONLY) {
            return Err(Error(-2));
        }
        &mut *local.aligned
    } else {
        v_owned = vec![0; v_size].into_boxed_slice();
        &mut *v_owned
    };

    let b_size = 32 * (r as usize) * (p as usize);
    let mut b = vec![0u32; b_size].into_boxed_slice();
    let mut xy = vec![0u32; 64 * (r as usize)].into_boxed_slice();

    if !flags.is_empty() {
        HMAC_SHA256_Buf(
            c"yescrypt-prehash".as_ptr() as *const c_void,
            if flags.contains(Flags::PREHASH) {
                16
            } else {
                8
            },
            passwd as *const c_void,
            passwdlen,
            sha256.as_mut_ptr() as *mut u8,
        );
        passwd = sha256.as_mut_ptr() as *mut u8;
        passwdlen = size_of::<[u32; 8]>();
    }

    PBKDF2_SHA256(
        passwd,
        passwdlen,
        salt.as_ptr(),
        salt.len(),
        1,
        b.as_mut_ptr().cast(),
        b_size * 4,
    );

    if !flags.is_empty() {
        sha256.copy_from_slice(&b[..8]);
    }

    if flags.contains(Flags::RW) {
        let s = malloc((3 * (1 << 8) * 2 * 8) * (p as usize)) as *mut u32;
        if s.is_null() {
            return Err(Error(-1));
        }

        let pwxform_ctx = PwxformCtx::alloc(p, s)?;

        smix::smix(
            b.as_mut_ptr(),
            r as usize,
            n,
            p,
            t,
            flags,
            v.as_mut_ptr(),
            xy.as_mut_ptr(),
            pwxform_ctx,
            sha256.as_mut_ptr() as *mut u8,
        );

        free(pwxform_ctx as *mut c_void);
        free(s as *mut c_void);
    } else {
        for i in 0..p {
            smix::smix(
                b[32usize.wrapping_mul(r as usize).wrapping_mul(i as usize)..].as_mut_ptr(),
                r as usize,
                n,
                1,
                t,
                flags,
                v.as_mut_ptr(),
                xy.as_mut_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
            );
        }
    }

    let mut dkp = out.as_mut_ptr();

    if !flags.is_empty() && out.len() < 32 {
        PBKDF2_SHA256(
            passwd,
            passwdlen,
            b.as_ptr().cast(),
            b_size * 4,
            1,
            dk.as_mut_ptr(),
            32,
        );
        dkp = dk.as_mut_ptr();
    }

    PBKDF2_SHA256(
        passwd,
        passwdlen,
        b.as_ptr().cast(),
        b_size * 4,
        1,
        out.as_mut_ptr(),
        out.len(),
    );

    if !flags.is_empty() && !flags.contains(Flags::PREHASH) {
        HMAC_SHA256_Buf(
            dkp as *const c_void,
            32,
            b"Client Key\0" as *const u8 as *const i8 as *const c_void,
            10,
            sha256.as_mut_ptr() as *mut u8,
        );
        let mut clen: usize = out.len();
        if clen > 32 {
            clen = 32;
        }
        SHA256_Buf(
            sha256.as_mut_ptr() as *mut u8 as *const c_void,
            size_of::<[u32; 8]>(),
            dk.as_mut_ptr(),
        );
        memcpy(
            out.as_mut_ptr() as *mut c_void,
            dk.as_mut_ptr() as *const c_void,
            clen,
        );
    }

    Ok(())
}
