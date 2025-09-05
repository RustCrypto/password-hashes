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
    pwxform::{PwxformCtx, RMIN, SWORDS},
    sha256::{HMAC_SHA256_Buf, PBKDF2_SHA256, SHA256_Buf},
};
use alloc::{boxed::Box, vec, vec::Vec};
use core::ptr;

#[derive(Clone)]
struct Local {
    pub aligned: Box<[u32]>,
}

/// yescrypt Key Derivation Function (KDF)
pub fn yescrypt_kdf(passwd: &[u8], salt: &[u8], params: &Params, out: &mut [u8]) -> Result<()> {
    let mut local = Local {
        aligned: Vec::new().into_boxed_slice(),
    };

    if params.g != 0 {
        return Err(Error);
    }

    if params.flags.contains(Flags::RW)
        && params.p >= 1
        && (params.n / params.p as u64) >= 0x100
        && params.n / (params.p as u64) / (params.r as u64) >= 0x20000
    {
        return Err(Error);
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

    match flags & Flags::MODE_MASK {
        // 0 (masking and bitflags play somewhat oddly together)
        Flags::ROUNDS_3 => {
            // classic scrypt - can't have anything non-standard
            if !flags.is_empty() || t != 0 || nrom != 0 {
                return Err(Error);
            }
        }
        Flags::WORM => {
            if flags != Flags::WORM || nrom != 0 {
                return Err(Error);
            }
        }
        Flags::RW => {
            if flags
                != flags
                    & (Flags::MODE_MASK
                        | Flags::RW_FLAVOR_MASK
                        | Flags::SHARED_PREALLOCATED
                        | Flags::INIT_SHARED
                        | Flags::ALLOC_ONLY
                        | Flags::PREHASH)
            {
                return Err(Error);
            }

            if (flags & Flags::RW_FLAVOR_MASK)
                != (Flags::ROUNDS_6 | Flags::GATHER_4 | Flags::SIMPLE_2 | Flags::SBOX_12K)
            {
                return Err(Error);
            }
        }
        _ => {
            return Err(Error);
        }
    }
    if !((out.len() as u64 <= u32::MAX as u64 * 32)
        && ((r as u64) * (p as u64) < (1 << 30) as u64)
        && !(n & (n - 1) != 0 || n <= 1 || r < 1 || p < 1)
        && !(r as u64 > u64::MAX / 128 / (p as u64) || n > u64::MAX / 128 / (r as u64))
        && (n <= u64::MAX / ((t as u64) + 1)))
    {
        return Err(Error);
    }

    if flags.contains(Flags::RW)
        && (n / (p as u64) <= 1
            || r < RMIN as u32
            || p as u64 > u64::MAX / (3 * (1 << 8) * 2 * 8)
            || p as u64 > u64::MAX / (size_of::<PwxformCtx<'_>>() as u64))
    {
        return Err(Error);
    }

    if nrom != 0 {
        return Err(Error);
    }

    let mut v_owned: Box<[u32]>;
    let v_size = 32 * (r as usize) * (n as usize);
    let v = if flags.contains(Flags::INIT_SHARED) {
        if local.aligned.len() < v_size {
            // why can't we just reallocate here?
            if !local.aligned.is_empty() {
                return Err(Error);
            }

            local.aligned = vec![0; v_size].into_boxed_slice();
        }
        if flags.contains(Flags::ALLOC_ONLY) {
            return Err(Error);
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
            c"yescrypt-prehash".as_ptr() as *const u8,
            if flags.contains(Flags::PREHASH) {
                16
            } else {
                8
            },
            passwd,
            passwdlen,
            sha256.as_mut_ptr() as *mut u8,
        );
        passwd = sha256.as_mut_ptr() as *mut u8;
        passwdlen = size_of::<[u32; 8]>();
    }

    // 1: (B_0 ... B_{p-1}) <-- PBKDF2(P, S, 1, p * MFLen)
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
        let mut s = vec![0u32; SWORDS * p as usize];
        let mut pwxform_ctx = PwxformCtx::new(p as usize, &mut s);

        smix::smix(
            &mut b,
            r as usize,
            n,
            p,
            t,
            flags,
            v.as_mut_ptr(),
            xy.as_mut_ptr(),
            pwxform_ctx.as_mut_slice(),
            sha256.as_mut_ptr() as *mut u8,
        );
    } else {
        // 2: for i = 0 to p - 1 do
        for i in 0..p {
            // 3: B_i <-- MF(B_i, N)
            smix::smix(
                &mut b[(32 * (r as usize) * (i as usize))..],
                r as usize,
                n,
                1,
                t,
                flags,
                v.as_mut_ptr(),
                xy.as_mut_ptr(),
                &mut [],
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

    // 5: DK <-- PBKDF2(P, B, 1, dkLen)
    PBKDF2_SHA256(
        passwd,
        passwdlen,
        b.as_ptr().cast(),
        b_size * 4,
        1,
        out.as_mut_ptr(),
        out.len(),
    );

    // Except when computing classic scrypt, allow all computation so far
    // to be performed on the client.  The final steps below match those of
    // SCRAM (RFC 5802), so that an extension of SCRAM (with the steps so
    // far in place of SCRAM's use of PBKDF2 and with SHA-256 in place of
    // SCRAM's use of SHA-1) would be usable with yescrypt hashes.
    if !flags.is_empty() && !flags.contains(Flags::PREHASH) {
        // Compute ClientKey
        HMAC_SHA256_Buf(
            dkp,
            32,
            c"Client Key".as_ptr() as *const u8,
            10,
            sha256.as_mut_ptr() as *mut u8,
        );

        // Compute StoredKey
        let mut clen: usize = out.len();
        if clen > 32 {
            clen = 32;
        }
        SHA256_Buf(
            sha256.as_mut_ptr() as *const u8,
            size_of::<[u32; 8]>(),
            dk.as_mut_ptr(),
        );
        ptr::copy_nonoverlapping(dk.as_mut_ptr(), out.as_mut_ptr(), clen);
    }

    Ok(())
}
