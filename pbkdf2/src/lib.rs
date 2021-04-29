//! This crate implements the PBKDF2 key derivation function as specified
//! in [RFC 2898](https://tools.ietf.org/html/rfc2898).
//!
//! If you are only using the low-level [`pbkdf2`] function instead of the
//! higher-level [`Pbkdf2`] struct to produce/verify hash strings,
//! it's recommended to disable default features in your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! pbkdf2 = { version = "0.7", default-features = false }
//! ```
//!
//! # Usage (simple with default params)
//!
//! Note: this example requires the `rand_core` crate with the `std` feature
//! enabled for `rand_core::OsRng` (embedded platforms can substitute their
//! own RNG)
//!
//! Add the following to your crate's `Cargo.toml` to import it:
//!
//! ```toml
//! [dependencies]
//! pbkdf2 = "0.7"
//! rand_core = { version = "0.6", features = ["std"] }
//! ```
//!
//! The following example demonstrates the high-level password hashing API:
//!
//! ```
//! # #[cfg(feature = "password-hash")]
//! # {
//! use pbkdf2::{
//!     password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
//!     Pbkdf2
//! };
//! use rand_core::OsRng;
//!
//! let password = b"hunter42"; // Bad password; don't actually use!
//! let salt = SaltString::generate(&mut OsRng);
//!
//! // Hash password to PHC string ($pbkdf2-sha256$...)
//! let password_hash = Pbkdf2.hash_password_simple(password, salt.as_ref()).unwrap().to_string();
//!
//! // Verify password against PHC string
//! let parsed_hash = PasswordHash::new(&password_hash).unwrap();
//! assert!(Pbkdf2.verify_password(password, &parsed_hash).is_ok());
//! # }
//! ```

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "simple")]
extern crate alloc;

#[cfg(feature = "simple")]
#[cfg_attr(docsrs, doc(cfg(feature = "simple")))]
pub use password_hash;

#[cfg(feature = "simple")]
mod simple;

#[cfg(feature = "simple")]
pub use crate::simple::{Algorithm, Params, Pbkdf2};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crypto_mac::generic_array::typenum::Unsigned;
use crypto_mac::{Mac, NewMac};

#[inline(always)]
fn xor(res: &mut [u8], salt: &[u8]) {
    debug_assert!(salt.len() >= res.len(), "length mismatch in xor");
    res.iter_mut().zip(salt.iter()).for_each(|(a, b)| *a ^= b);
}

#[inline(always)]
fn pbkdf2_body<F>(i: u32, chunk: &mut [u8], prf: &F, salt: &[u8], rounds: u32)
where
    F: Mac + Clone,
{
    for v in chunk.iter_mut() {
        *v = 0;
    }

    let mut salt = {
        let mut prfc = prf.clone();
        prfc.update(salt);
        prfc.update(&(i + 1).to_be_bytes());

        let salt = prfc.finalize().into_bytes();
        xor(chunk, &salt);
        salt
    };

    for _ in 1..rounds {
        let mut prfc = prf.clone();
        prfc.update(&salt);
        salt = prfc.finalize().into_bytes();

        xor(chunk, &salt);
    }
}

/// Generic implementation of PBKDF2 algorithm.
#[cfg(feature = "parallel")]
#[inline]
pub fn pbkdf2<F>(password: &[u8], salt: &[u8], rounds: u32, res: &mut [u8])
where
    F: Mac + NewMac + Clone + Sync,
{
    let n = F::OutputSize::to_usize();
    let prf = F::new_from_slice(password).expect("HMAC accepts all key sizes");

    res.par_chunks_mut(n).enumerate().for_each(|(i, chunk)| {
        pbkdf2_body(i as u32, chunk, &prf, salt, rounds);
    });
}

/// Generic implementation of PBKDF2 algorithm.
#[cfg(not(feature = "parallel"))]
#[inline]
pub fn pbkdf2<F>(password: &[u8], salt: &[u8], rounds: u32, res: &mut [u8])
where
    F: Mac + NewMac + Clone + Sync,
{
    let n = F::OutputSize::to_usize();
    let prf = F::new_from_slice(password).expect("HMAC accepts all key sizes");

    for (i, chunk) in res.chunks_mut(n).enumerate() {
        pbkdf2_body(i as u32, chunk, &prf, salt, rounds);
    }
}
