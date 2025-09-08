#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![warn(
    // TODO: clippy::cast_lossless,
    // TODO: clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::checked_conversions,
    clippy::implicit_saturating_sub,
    clippy::panic,
    clippy::panic_in_result_fn,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

//! # Usage
//! ## Password Hashing
//! NOTE: the `simple` crate feature must be enabled (on-by-default)
#![cfg_attr(feature = "simple", doc = "```")]
#![cfg_attr(not(feature = "simple"), doc = "```ignore")]
//! # fn main() -> yescrypt::Result<()> {
//! let password = b"pleaseletmein"; // don't actually use this as a password!
//! let salt = b"WZaPV7LSUEKMo34."; // unique per password, ideally 16-bytes and random
//! let password_hash = yescrypt::yescrypt(password, salt, &Default::default())?;
//! assert_eq!(&password_hash[..3], "$y$");
//! # Ok(())
//! # }
//! ```
//!
//! ## Key Derivation Function (KDF)
#![cfg_attr(feature = "simple", doc = "```")]
#![cfg_attr(not(feature = "simple"), doc = "```ignore")]
//! # fn main() -> yescrypt::Result<()> {
//! let password = b"pleaseletmein"; // don't actually use this as a password!
//! let salt = b"WZaPV7LSUEKMo34."; // unique per password, ideally 16-bytes and random
//!
//! let mut output = [0u8; 32]; // can be sized as desired
//! yescrypt::yescrypt_kdf(password, salt, &Default::default(), &mut output)?;
//! # Ok(())
//! # }
//! ```

// Adapted from the yescrypt reference implementation available at:
// <https://github.com/openwall/yescrypt>
//
// Relicensed from the BSD-2-Clause license to Apache 2.0+MIT with permission:
// <https://github.com/openwall/yescrypt/issues/7>

extern crate alloc;

mod encoding;
mod error;
mod flags;
mod params;
mod pwxform;
mod salsa20;
mod smix;
mod util;

pub use crate::{
    error::{Error, Result},
    flags::Flags,
    params::Params,
};

use crate::pwxform::{PwxformCtx, RMIN};
use alloc::{boxed::Box, vec, vec::Vec};
use sha2::{Digest, Sha256};

#[cfg(feature = "simple")]
use alloc::string::String;

/// Identifier for yescrypt when encoding to the Modular Crypt Format, i.e. `$y$`
#[cfg(feature = "simple")]
const YESCRYPT_MCF_ID: &str = "y";

#[derive(Clone)]
struct Local {
    pub aligned: Box<[u32]>,
}

/// yescrypt password hashing function.
///
/// This function produces an (s)crypt-style password hash string starting with the prefix `$y$`.
///
/// If using yescrypt as a key derivation, consider [`yescrypt_kdf`] instead.
#[cfg(feature = "simple")]
pub fn yescrypt(passwd: &[u8], salt: &[u8], params: &Params) -> Result<String> {
    // TODO(tarcieri): tunable hash output size?
    const HASH_SIZE: usize = 32;

    let mut out = [0u8; HASH_SIZE];
    yescrypt_kdf(passwd, salt, params, &mut out)?;

    // Begin building the Modular Crypt Format hash.
    let mut mcf_hash = mcf::PasswordHash::from_id(YESCRYPT_MCF_ID).expect("should be valid");

    // Add params string to the hash
    let mut params_buf = [0u8; Params::MAX_ENCODED_LEN];
    let params_str = params.encode(&mut params_buf)?;
    let field = mcf::Field::new(params_str).map_err(|_| Error)?;
    mcf_hash.push_field(field);

    let mut buf = [0u8; (HASH_SIZE * 4).div_ceil(3)];

    // Add salt
    // TODO(tarcieri): use `mcf` crate's Base64 support
    mcf_hash
        .push_str(encoding::encode64(salt, &mut buf)?)
        .map_err(|_| Error)?;

    // Add yescrypt output
    mcf_hash
        .push_str(encoding::encode64(&out, &mut buf)?)
        .map_err(|_| Error)?;

    // Convert to a normal `String` to keep `mcf` out of the public API (for now)
    Ok(mcf_hash.into())
}

/// yescrypt Key Derivation Function (KDF)
pub fn yescrypt_kdf(passwd: &[u8], salt: &[u8], params: &Params, out: &mut [u8]) -> Result<()> {
    let mut local = Local {
        aligned: Vec::new().into_boxed_slice(),
    };

    if params.g != 0 {
        return Err(Error);
    }

    // Perform conditional pre-hashing
    let mut dk = [0u8; 32];
    let passwd = if params.flags.contains(Flags::RW)
        && params.p >= 1
        && params.n / (params.p as u64) >= 0x100
        && params.n / (params.p as u64) * (params.r as u64) >= 0x20000
    {
        yescrypt_kdf_body(
            &mut local,
            passwd,
            salt,
            params.flags | Flags::PREHASH,
            params.n >> 6,
            params.r,
            params.p,
            0,
            params.nrom,
            &mut dk,
        )?;

        &dk
    } else {
        passwd
    };

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

/// Compute yescrypt and write the result into `out`.
///
/// - `flags` may request special modes.
/// - `t` controls computation time while not affecting peak memory usage.
#[allow(clippy::too_many_arguments)]
fn yescrypt_kdf_body(
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
    let mut passwd = passwd;

    let mut sha256 = [0u8; 32];
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
        sha256 = util::hmac_sha256(
            if flags.contains(Flags::PREHASH) {
                &b"yescrypt-prehash"[..]
            } else {
                &b"yescrypt"[..]
            },
            passwd,
        );
        passwd = &sha256;
    }

    // 1: (B_0 ... B_{p-1}) <-- PBKDF2(P, S, 1, p * MFLen)
    pbkdf2::pbkdf2_hmac::<Sha256>(passwd, salt, 1, util::cast_slice_mut(&mut b));

    if !flags.is_empty() {
        sha256.copy_from_slice(util::cast_slice(&b[..8]));
        passwd = &sha256;
    }

    if flags.contains(Flags::RW) {
        smix::smix(&mut b, r as usize, n, p, t, flags, v, &mut xy, &mut sha256);
        passwd = &sha256;
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
                v,
                &mut xy,
                &mut [],
            );
        }
    }

    if !flags.is_empty() && out.len() < 32 {
        pbkdf2::pbkdf2_hmac::<Sha256>(passwd, util::cast_slice(&b), 1, &mut dk);
    }

    // 5: DK <-- PBKDF2(P, B, 1, dkLen)
    pbkdf2::pbkdf2_hmac::<Sha256>(passwd, util::cast_slice(&b), 1, out);

    // Except when computing classic scrypt, allow all computation so far
    // to be performed on the client.  The final steps below match those of
    // SCRAM (RFC 5802), so that an extension of SCRAM (with the steps so
    // far in place of SCRAM's use of PBKDF2 and with SHA-256 in place of
    // SCRAM's use of SHA-1) would be usable with yescrypt hashes.
    if !flags.is_empty() && !flags.contains(Flags::PREHASH) {
        let dkp = if !flags.is_empty() && out.len() < 32 {
            &mut dk
        } else {
            &mut *out
        };

        // Compute ClientKey
        sha256 = util::hmac_sha256(&dkp[..32], b"Client Key");

        // Compute StoredKey
        let clen = out.len().clamp(0, 32);
        dk = Sha256::digest(sha256).into();
        out[..clen].copy_from_slice(&dk[..clen]);
    }

    Ok(())
}
