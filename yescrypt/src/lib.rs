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
//! ```
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

use alloc::vec;
use sha2::{Digest, Sha256};

#[cfg(feature = "simple")]
use alloc::string::String;

/// Identifier for yescrypt when encoding to the Modular Crypt Format, i.e. `$y$`
#[cfg(feature = "simple")]
const YESCRYPT_MCF_ID: &str = "y";

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
    let field = mcf::Field::new(params_str).map_err(|_| Error::Encoding)?;
    mcf_hash.push_field(field);

    let mut buf = [0u8; (HASH_SIZE * 4).div_ceil(3)];

    // Add salt
    // TODO(tarcieri): use `mcf` crate's Base64 support
    mcf_hash
        .push_str(encoding::encode64(salt, &mut buf)?)
        .map_err(|_| Error::Encoding)?;

    // Add yescrypt output
    mcf_hash
        .push_str(encoding::encode64(&out, &mut buf)?)
        .map_err(|_| Error::Encoding)?;

    // Convert to a normal `String` to keep `mcf` out of the public API (for now)
    Ok(mcf_hash.into())
}

/// Verify a password matches the given yescrypt password hash.
///
/// Password hash should begin with `$y$` in Modular Crypt Format (MCF).
pub fn yescrypt_verify(passwd: &[u8], hash: &str) -> Result<()> {
    let hash = mcf::PasswordHashRef::try_from(hash).map_err(|_| Error::Encoding)?;

    // verify id matches `$y`
    if hash.id() != YESCRYPT_MCF_ID {
        return Err(Error::Algorithm);
    }

    let mut fields = hash.fields();

    // decode params
    let params: Params = fields.next().ok_or(Error::Encoding)?.as_str().parse()?;

    // decode salt
    // TODO(tarcieri): use `mcf` crate's Base64 support
    let mut salt_buf = [0u8; 16]; // TODO(tarcieri): support larger salts?
    let salt_str = fields.next().ok_or(Error::Encoding)?.as_str();
    let salt = encoding::decode64(salt_str, &mut salt_buf)?;

    // decode expected password hash
    const MAX_HASH_SIZE: usize = 32; // TODO(tarcieri): support larger outputs?
    let mut expected_buf = [0u8; MAX_HASH_SIZE];
    let expected_str = fields.next().ok_or(Error::Encoding)?.as_str();
    let expected = encoding::decode64(expected_str, &mut expected_buf)?;

    // should be the last field
    if fields.next().is_some() {
        return Err(Error::Encoding);
    }

    let mut actual_buf = [0u8; MAX_HASH_SIZE];
    let actual = &mut actual_buf[..expected.len()];
    yescrypt_kdf(passwd, salt, &params, actual)?;

    // TODO(tarcieri): constant-time comparison?
    if expected != actual {
        return Err(Error::Password);
    }

    Ok(())
}

/// yescrypt Key Derivation Function (KDF)
pub fn yescrypt_kdf(passwd: &[u8], salt: &[u8], params: &Params, out: &mut [u8]) -> Result<()> {
    // Perform conditional pre-hashing
    let mut passwd = passwd;
    let mut dk = [0u8; 32];
    if params.flags.contains(Flags::RW)
        && params.p >= 1
        && params.n / (params.p as u64) >= 0x100
        && params.n / (params.p as u64) * (params.r as u64) >= 0x20000
    {
        let mut prehash_params = *params;
        prehash_params.flags |= Flags::PREHASH;
        prehash_params.n >>= 6;
        prehash_params.t = 0;

        yescrypt_kdf_body(passwd, salt, &prehash_params, &mut dk)?;

        // Use derived key as the "password" for the subsequent step
        passwd = &dk;
    }

    yescrypt_kdf_body(passwd, salt, params, out)
}

/// Compute yescrypt and write the result into `out`.
///
/// - `flags` may request special modes.
/// - `t` controls computation time while not affecting peak memory usage.
fn yescrypt_kdf_body(passwd: &[u8], salt: &[u8], params: &Params, out: &mut [u8]) -> Result<()> {
    let flags: Flags = params.flags;
    let n: u64 = params.n;
    let r: u32 = params.r;
    let p: u32 = params.p;
    let t: u32 = params.t;

    if !((out.len() as u64 <= u32::MAX as u64 * 32)
        && ((r as u64) * (p as u64) < (1 << 30) as u64)
        && !(n & (n - 1) != 0 || n <= 1 || r < 1 || p < 1)
        && !(r as u64 > u64::MAX / 128 / (p as u64) || n > u64::MAX / 128 / (r as u64))
        && (n <= u64::MAX / ((t as u64) + 1)))
    {
        return Err(Error::Params);
    }

    let mut v = vec![0; 32 * (r as usize) * (n as usize)];
    let mut b = vec![0; 32 * (r as usize) * (p as usize)];
    let mut xy = vec![0; 64 * (r as usize)];

    let mut passwd = passwd;
    let mut sha256 = [0u8; 32];
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
        smix::smix(&mut b, r, n, p, t, flags, &mut v, &mut xy, &mut sha256);
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
                flags,
                &mut v,
                &mut xy,
                &mut [],
            );
        }
    }

    let mut dk = [0u8; 32];
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
