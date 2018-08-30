//! This crate implements the PBKDF2 key derivation function as specified
//! in [RFC 2898](https://tools.ietf.org/html/rfc2898).
//!
//! If you are not using convinience functions `pbkdf2_check` and `pbkdf2_simple`
//! it's recommended to disable `pbkdf2` default features in your `Cargo.toml`:
//! ```toml
//! [dependencies]
//! pbkdf2 = { version = "0.2", default-features = false }
//! ```
#![cfg_attr(not(feature = "include_simple"), no_std)]
#![cfg_attr(feature = "cargo-clippy", allow(inline_always))]
extern crate crypto_mac;
extern crate generic_array;
extern crate byteorder;

#[cfg(feature="parallel")]
extern crate rayon;
#[cfg(feature="parallel")]
use rayon::prelude::*;

use crypto_mac::Mac;
use generic_array::typenum::Unsigned;
use byteorder::{ByteOrder, BigEndian};

#[cfg(feature="include_simple")]
extern crate constant_time_eq;
#[cfg(feature="include_simple")]
extern crate base64;
#[cfg(feature="include_simple")]
extern crate rand;
#[cfg(feature="include_simple")]
extern crate hmac;
#[cfg(feature="include_simple")]
extern crate sha2;

#[cfg(feature="include_simple")]
use std::io;

#[cfg(feature="include_simple")]
use constant_time_eq::constant_time_eq;
#[cfg(feature="include_simple")]
use rand::{OsRng, RngCore};
#[cfg(feature="include_simple")]
use hmac::Hmac;
#[cfg(feature="include_simple")]
use sha2::Sha256;

#[cfg(feature="include_simple")]
mod errors;
#[cfg(feature="include_simple")]
pub use errors::CheckError;

#[inline(always)]
fn xor(res: &mut [u8], salt: &[u8]) {
    debug_assert!(salt.len() >= res.len(), "length mismatch in xor");

    res.iter_mut().zip(salt.iter()).for_each(|(a, b)| *a ^= b);
}

#[inline(always)]
fn pbkdf2_body<F>(i: usize, chunk: &mut [u8], prf: &F, salt: &[u8], c: usize)
    where F: Mac + Clone
{
    for v in chunk.iter_mut() { *v = 0; }

    let mut salt = {
        let mut prfc = prf.clone();
        prfc.input(salt);

        let mut buf = [0u8; 4];
        BigEndian::write_u32(&mut buf, (i + 1) as u32);
        prfc.input(&buf);

        let salt = prfc.result().code();
        xor(chunk, &salt);
        salt
    };

    for _ in 1..c {
        let mut prfc = prf.clone();
        prfc.input(&salt);
        salt = prfc.result().code();

        xor(chunk, &salt);
    }
}

/// Generic implementation of PBKDF2 algorithm.
#[cfg(feature="parallel")]
#[inline]
pub fn pbkdf2<F>(password: &[u8], salt: &[u8], c: usize, res: &mut [u8])
    where F: Mac + Clone + Sync
{
    let n = F::OutputSize::to_usize();
    let prf = F::new_varkey(password).expect("HMAC accepts all key sizes");

    res.par_chunks_mut(n).enumerate().for_each(|(i, chunk)| {
        pbkdf2_body(i, chunk, &prf, salt, c);
    });
}

/// Generic implementation of PBKDF2 algorithm.
#[cfg(not(feature="parallel"))]
#[inline]
pub fn pbkdf2<F>(password: &[u8], salt: &[u8], c: usize, res: &mut [u8])
    where F: Mac + Clone + Sync
{
    let n = F::OutputSize::to_usize();
    let prf = F::new_varkey(password).expect("HMAC accepts all key sizes");

    for (i, chunk) in res.chunks_mut(n).enumerate() {
        pbkdf2_body(i, chunk, &prf, salt, c);
    }
}


/// A helper function that should be sufficient for the majority of cases where
/// an application needs to use PBKDF2 to hash a password for storage.
///
/// Internally it uses PBKDF2-HMAC-SHA256 algorithm. The result is a `String`
/// that contains the parameters used as part of its encoding. The `pbkdf2_check`
/// function may be used on a password to check if it is equal to a hashed value.
///
/// # Format
///
/// The format of the output is a modified version of the Modular Crypt Format
/// that encodes algorithm used and iteration count. The format is indicated as
/// "rpbkdf2" which is short for "Rust PBKF2 format."
///
/// ```text
/// $rpbkdf2$0$<base64(c)>$<base64(salt)>$<based64(hash)>$
/// ```
///
/// # Arguments
///
/// * `password` - The password to process
/// * `c` - The iteration count
#[cfg(feature="include_simple")]
pub fn pbkdf2_simple(password: &str, c: u32) -> io::Result<String> {
    let mut rng = OsRng::new()?;

    // 128-bit salt
    let mut salt = [0u8; 16];
    rng.try_fill_bytes(&mut salt)?;

    // 256-bit derived key
    let mut dk = [0u8; 32];

    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &salt, c as usize, &mut dk);

    let mut result = "$rpbkdf2$0$".to_string();
    let mut tmp = [0u8; 4];
    BigEndian::write_u32(&mut tmp, c);
    result.push_str(&base64::encode(&tmp));
    result.push('$');
    result.push_str(&base64::encode(&salt));
    result.push('$');
    result.push_str(&base64::encode(&dk));
    result.push('$');

    Ok(result)
}

/// Compares a password against the result of a `pbkdf2_simple`.
///
/// It will return `Ok(())` if `password` hashes to the same value, if hashes
/// are different it will return `Err(CheckError::HashMismatch)`, and
/// `Err(CheckError::InvalidFormat)` if `hashed_value` has an invalid format.
///
/// # Arguments
/// * `password` - The password to process
/// * `hashed_value` - A string representing a hashed password returned by
/// `pbkdf2_simple`
#[cfg(feature="include_simple")]
pub fn pbkdf2_check(password: &str, hashed_value: &str)
    -> Result<(), self::errors::CheckError> {
    let mut iter = hashed_value.split('$');

    // Check that there are no characters before the first "$"
    if iter.next() != Some("") { Err(CheckError::InvalidFormat)?; }

    // Check the name
    if iter.next() != Some("rpbkdf2") { Err(CheckError::InvalidFormat)?; }

    // Parse format - currenlty only version 0 is supported
    match iter.next() {
        Some(fstr) => {
            match fstr {
                "0" => { }
                _ => return Err(CheckError::InvalidFormat)
            }
        }
        None => return Err(CheckError::InvalidFormat)
    }

    // Parse the iteration count
    let c = match iter.next() {
        Some(pstr) => match base64::decode(pstr) {
            Ok(pvec) => {
                if pvec.len() != 4 { return Err(CheckError::InvalidFormat); }
                BigEndian::read_u32(&pvec[..])
            }
            Err(_) => return Err(CheckError::InvalidFormat)
        },
        None => return Err(CheckError::InvalidFormat)
    };

    // Salt
    let salt = match iter.next() {
        Some(sstr) => match base64::decode(sstr) {
            Ok(salt) => salt,
            Err(_) => return Err(CheckError::InvalidFormat)
        },
        None => return Err(CheckError::InvalidFormat)
    };

    // Hashed value
    let hash = match iter.next() {
        Some(hstr) => match base64::decode(hstr) {
            Ok(hash) => hash,
            Err(_) => return Err(CheckError::InvalidFormat)
        },
        None => return Err(CheckError::InvalidFormat)
    };

    // Make sure that the input ends with a "$"
    if iter.next() != Some("") { Err(CheckError::InvalidFormat)?; }

    // Make sure there is no trailing data after the final "$"
    if iter.next() != None { Err(CheckError::InvalidFormat)?; }

    let mut output = vec![0u8; hash.len()];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &salt, c as usize, &mut output);

    // Be careful here - its important that the comparison be done using a fixed
    // time equality check. Otherwise an adversary that can measure how long
    // this step takes can learn about the hashed value which would allow them
    // to mount an offline brute force attack against the hashed password.
    if constant_time_eq(&output, &hash) {
        Ok(())
    } else {
        Err(CheckError::HashMismatch)
    }
}
