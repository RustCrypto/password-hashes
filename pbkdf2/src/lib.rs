//! This crate implements the PBKDF2 key derivation function as specified
//! in [RFC 2898](https://tools.ietf.org/html/rfc2898).
//!
//! If you are not using convinience functions `pbkdf2_check` and `pbkdf2_simple`
//! it's recommended to disable `pbkdf2` default features in your `Cargo.toml`:
//! ```toml
//! [dependencies]
//! pbkdf2 = { version = "0.2", default-features = false }
//! ```
#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![cfg_attr(feature = "cargo-clippy", allow(inline_always))]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "include_simple")]
extern crate alloc;

mod errors;
mod simple;

#[cfg(feature = "include_simple")]
pub use crate::errors::CheckError;
#[cfg(feature = "include_simple")]
pub use crate::simple::{pbkdf2_check, pbkdf2_simple};

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
    let prf = F::new_varkey(password).expect("HMAC accepts all key sizes");

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
    let prf = F::new_varkey(password).expect("HMAC accepts all key sizes");

    for (i, chunk) in res.chunks_mut(n).enumerate() {
        pbkdf2_body(i as u32, chunk, &prf, salt, rounds);
    }
}
