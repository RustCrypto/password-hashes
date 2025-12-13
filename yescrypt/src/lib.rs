#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![deny(unsafe_code)]
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
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

//! # Usage
//! ## Password Hashing
#![cfg_attr(feature = "getrandom", doc = "```")]
#![cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
//! # fn main() -> yescrypt::password_hash::Result<()> {
//! // NOTE: example requires `getrandom` feature is enabled
//!
//! use yescrypt::{Yescrypt, PasswordHasher, PasswordVerifier};
//!
//! let password = b"pleaseletmein"; // don't actually use this as a password!
//! let password_hash = Yescrypt.hash_password(password)?;
//! assert!(password_hash.as_str().starts_with("$y$"));
//!
//! // verify password is correct for the given hash
//! Yescrypt.verify_password(password, &password_hash)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Key Derivation Function (KDF)
//! ```
//! # fn main() -> yescrypt::Result<()> {
//! let password = b"pleaseletmein"; // don't actually use this as a password!
//! let salt = b"WZaPV7LSUEKMo34."; // unique per password, ideally 16-bytes and random
//! let params = yescrypt::Params::default(); // use recommended settings
//!
//! let mut output = [0u8; 32]; // can be sized as desired
//! yescrypt::yescrypt(password, salt, &params, &mut output)?;
//! # Ok(())
//! # }
//! ```

// Adapted from the yescrypt reference implementation available at:
// <https://github.com/openwall/yescrypt>
//
// Relicensed from the BSD-2-Clause license to Apache 2.0+MIT with permission:
// <https://github.com/openwall/yescrypt/issues/7>

extern crate alloc;

mod error;
mod mode;
mod params;
mod pwxform;
mod salsa20;
mod smix;
mod util;

#[cfg(feature = "password-hash")]
mod mcf;

pub use crate::{
    error::{Error, Result},
    mode::Mode,
    params::Params,
};

#[cfg(feature = "password-hash")]
pub use {
    crate::mcf::{PasswordHash, PasswordHashRef, Yescrypt},
    password_hash::{self, CustomizedPasswordHasher, PasswordHasher, PasswordVerifier},
};

use alloc::vec;
use sha2::{Digest, Sha256};

/// yescrypt Key Derivation Function (KDF).
///
/// This is the low-level interface useful for producing cryptographic keys directly.
///
/// If you are looking for a higher-level interface which can express and store password hashes as
/// strings, please check out the [`Yescrypt`] type.
pub fn yescrypt(passwd: &[u8], salt: &[u8], params: &Params, out: &mut [u8]) -> Result<()> {
    let mut passwd = passwd;
    let mut dk = [0u8; 32];

    // Conditionally perform pre-hashing
    if params.mode.is_rw()
        && params.p >= 1
        && params.n / u64::from(params.p) >= 0x100
        && params.n / u64::from(params.p) * u64::from(params.r) >= 0x20000
    {
        let mut prehash_params = *params;
        prehash_params.n >>= 6;
        prehash_params.t = 0;
        yescrypt_body(passwd, salt, &prehash_params, true, &mut dk)?;

        // Use derived key as the "password" for the subsequent step when pre-hashing
        passwd = &dk;
    }

    yescrypt_body(passwd, salt, params, false, out)
}

/// Compute yescrypt and write the result into `out`.
fn yescrypt_body(
    passwd: &[u8],
    salt: &[u8],
    params: &Params,
    prehash: bool,
    out: &mut [u8],
) -> Result<()> {
    let mode = params.mode;
    let n = params.n;
    let r = params.r;
    let p = params.p;
    let t = params.t;

    if !((out.len() as u64 <= u64::from(u32::MAX) * 32)
        && (u64::from(r) * u64::from(p) < (1 << 30) as u64)
        && !(n & (n - 1) != 0 || n <= 1 || r < 1 || p < 1)
        && !(u64::from(r) > u64::MAX / 128 / u64::from(p) || n > u64::MAX / 128 / u64::from(r))
        && (n <= u64::MAX / (u64::from(t) + 1)))
    {
        return Err(Error::Params);
    }

    let mut v = vec![0; 32 * (r as usize) * usize::try_from(n)?];
    let mut b = vec![0; 32 * (r as usize) * (p as usize)];
    let mut xy = vec![0; 64 * (r as usize)];

    let mut passwd = passwd;
    let mut sha256 = [0u8; 32];
    let key: &[u8] = if prehash {
        b"yescrypt-prehash"
    } else {
        b"yescrypt"
    };
    if !mode.is_classic() {
        sha256 = util::hmac_sha256(key, passwd)?;
        passwd = &sha256;
    }

    // 1: (B_0 ... B_{p-1}) <-- PBKDF2(P, S, 1, p * MFLen)
    pbkdf2::pbkdf2_hmac::<Sha256>(passwd, salt, 1, util::cast_slice_mut(&mut b)?);

    if !mode.is_classic() {
        sha256.copy_from_slice(util::cast_slice(&b[..8])?);
        passwd = &sha256;
    }

    if mode.is_rw() {
        smix::smix(&mut b, r, n, p, t, mode, &mut v, &mut xy, &mut sha256)?;
        passwd = &sha256;
    } else {
        // 2: for i = 0 to p - 1 do
        for i in 0..p {
            // 3: B_i <-- MF(B_i, N)
            smix::smix(
                &mut b[(32 * (r as usize) * (i as usize))..],
                r,
                n,
                1,
                t,
                mode,
                &mut v,
                &mut xy,
                &mut [],
            )?;
        }
    }

    let mut dk = [0u8; 32];
    if !mode.is_classic() && out.len() < 32 {
        pbkdf2::pbkdf2_hmac::<Sha256>(passwd, util::cast_slice(&b)?, 1, &mut dk);
    }

    // 5: DK <-- PBKDF2(P, B, 1, dkLen)
    pbkdf2::pbkdf2_hmac::<Sha256>(passwd, util::cast_slice(&b)?, 1, out);

    // Except when computing classic scrypt, allow all computation so far
    // to be performed on the client.  The final steps below match those of
    // SCRAM (RFC 5802), so that an extension of SCRAM (with the steps so
    // far in place of SCRAM's use of PBKDF2 and with SHA-256 in place of
    // SCRAM's use of SHA-1) would be usable with yescrypt hashes.
    if !mode.is_classic() && !prehash {
        let dkp = if !mode.is_classic() && out.len() < 32 {
            &mut dk
        } else {
            &mut *out
        };

        // Compute ClientKey
        sha256 = util::hmac_sha256(&dkp[..32], b"Client Key")?;

        // Compute StoredKey
        let clen = out.len().clamp(0, 32);
        dk = Sha256::digest(sha256).into();
        out[..clen].copy_from_slice(&dk[..clen]);
    }

    Ok(())
}
