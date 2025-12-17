//! This crate implements the Scrypt key derivation function as specified
//! in \[1\].
//!
//! If you are only using the low-level [`scrypt`] function instead of the
//! higher-level [`Scrypt`] struct to produce/verify hash strings,
//! it's recommended to disable default features in your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! scrypt = { version = "0.2", default-features = false }
//! ```
//!
//! # Usage (simple with default params)
//!
#![cfg_attr(all(feature = "alloc", feature = "getrandom"), doc = "```")]
#![cfg_attr(not(all(feature = "alloc", feature = "getrandom")), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! // NOTE: example requires `getrandom` feature is enabled
//!
//! use scrypt::{
//!     password_hash::{
//!         PasswordHasher, PasswordVerifier, phc::{PasswordHash, Salt}
//!     },
//!     Scrypt
//! };
//!
//! let password = b"hunter42"; // Bad password; don't actually use!
//!
//! // Hash password to PHC string ($scrypt$...)
//! let hash: PasswordHash = Scrypt.hash_password(password)?;
//! let hash_string = hash.to_string();
//!
//! // Verify password against PHC string
//! let parsed_hash = PasswordHash::new(&hash_string)?;
//! assert!(Scrypt.verify_password(password, &parsed_hash).is_ok());
//! # Ok(())
//! # }
//! ```
//!
//! # References
//! \[1\] - [C. Percival. Stronger Key Derivation Via Sequential
//! Memory-Hard Functions](http://www.tarsnap.com/scrypt/scrypt.pdf)

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]

#[macro_use]
extern crate alloc;

use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

/// Errors for `scrypt` operations.
pub mod errors;
mod params;
mod romix;

#[cfg(feature = "mcf")]
pub mod mcf;
#[cfg(feature = "phc")]
pub mod phc;

pub use crate::params::Params;

#[cfg(feature = "password-hash")]
pub use password_hash;

#[cfg(all(doc, feature = "password-hash"))]
use password_hash::{CustomizedPasswordHasher, PasswordHasher, PasswordVerifier};

/// The scrypt key derivation function.
///
/// # Arguments
/// - `password` - The password to process as a byte vector
/// - `salt` - The salt value to use as a byte vector
/// - `params` - The ScryptParams to use
/// - `output` - The resulting derived key is returned in this byte vector.
///   **WARNING: Make sure to compare this value in constant time!**
///
/// # Return
/// `Ok(())` if calculation is successful and `Err(InvalidOutputLen)` if
/// `output` does not satisfy the following condition:
/// `output.len() > 0 && output.len() <= (2^32 - 1) * 32`.
///
/// # Note about output lengths
/// The output size is determined entirely by size of the `output` parameter.
///
/// If the length of the [`Params`] have been customized using the [`Params::new_with_output_len`]
/// constructor, that length is ignored and the length of `output` is used instead.
pub fn scrypt(
    password: &[u8],
    salt: &[u8],
    params: &Params,
    output: &mut [u8],
) -> Result<(), errors::InvalidOutputLen> {
    // This check required by Scrypt:
    // check output.len() > 0 && output.len() <= (2^32 - 1) * 32
    if output.is_empty() || output.len() / 32 > 0xffff_ffff {
        return Err(errors::InvalidOutputLen);
    }

    // The checks in the ScryptParams constructor guarantee
    // that the following is safe:
    let n = 1 << params.log_n;
    let r128 = (params.r as usize) * 128;
    let pr128 = (params.p as usize) * r128;
    let nr128 = n * r128;

    let mut b = vec![0u8; pr128];
    pbkdf2_hmac::<Sha256>(password, salt, 1, &mut b);

    #[cfg(not(feature = "rayon"))]
    romix_sequential(nr128, r128, n, &mut b);
    #[cfg(feature = "rayon")]
    romix_parallel(nr128, r128, n, &mut b);

    pbkdf2_hmac::<Sha256>(password, &b, 1, output);
    Ok(())
}

#[cfg(not(feature = "rayon"))]
fn romix_sequential(nr128: usize, r128: usize, n: usize, b: &mut [u8]) {
    let mut v = vec![0u8; nr128];
    let mut t = vec![0u8; r128];

    b.chunks_mut(r128).for_each(|chunk| {
        romix::scrypt_ro_mix(chunk, &mut v, &mut t, n);
    });
}

#[cfg(feature = "rayon")]
fn romix_parallel(nr128: usize, r128: usize, n: usize, b: &mut [u8]) {
    use rayon::{iter::ParallelIterator as _, slice::ParallelSliceMut as _};

    b.par_chunks_mut(r128).for_each(|chunk| {
        let mut v = vec![0u8; nr128];
        let mut t = vec![0u8; r128];
        romix::scrypt_ro_mix(chunk, &mut v, &mut t, n);
    });
}

/// scrypt password hashing type which can produce and verify strings in either the Password Hashing
/// Competition (PHC) string format which begin with `$scrypt$`, or in Modular Crypt Format (MCF)
/// which begin with `$7$`.
///
/// This is a ZST which impls traits from the [`password-hash`][`password_hash`] crate, notably
/// the [`PasswordHasher`], [`PasswordVerifier`], and [`CustomizedPasswordHasher`] traits.
///
/// See the toplevel documentation for a code example.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Scrypt;
