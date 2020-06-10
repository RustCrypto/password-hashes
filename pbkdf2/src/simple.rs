#![cfg(feature = "include_simple")]
use alloc::{vec, string::String};
use core::convert::TryInto;

use crate::errors::CheckError;
use base64;
use hmac::Hmac;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use rand_core::RngCore;

use super::pbkdf2;

#[cfg(not(features = "thread_rng"))]
type DefaultRng = rand_core::OsRng;
#[cfg(features = "thread_rng")]
type DefaultRng = rand::ThreadRng;

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
pub fn pbkdf2_simple(password: &str, rounds: u32) -> Result<String, rand_core::Error> {
    // 128-bit salt
    let mut salt = [0u8; 16];
    DefaultRng::default().try_fill_bytes(&mut salt)?;

    // 256-bit derived key
    let mut dk = [0u8; 32];

    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &salt, rounds, &mut dk);

    let mut result = String::with_capacity(90);
    result.push_str("$rpbkdf2$0$");
    result.push_str(&base64::encode(&rounds.to_be_bytes()));
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
pub fn pbkdf2_check(password: &str, hashed_value: &str) -> Result<(), CheckError> {
    let mut parts = hashed_value.split('$');
    // prevent dynamic allocations by using a fixed-size buffer
    let buf = [
        parts.next(), parts.next(), parts.next(), parts.next(),
        parts.next(), parts.next(), parts.next(), parts.next(),
    ];

    // check the format of the input: there may be no tokens before the first
    // and after the last `$`, tokens must have correct information and length.
    let (count, salt, hash) = match buf {
        [
            Some(""), Some("rpbkdf2"), Some("0"), Some(c),
            Some(s), Some(h), Some(""), None
        ] => (c, s, h),
        _ => return Err(CheckError::InvalidFormat),
    };

    let count_arr = base64::decode(count)?
        .as_slice()
        .try_into()
        .map_err(|_| CheckError::InvalidFormat)?;
    let count = u32::from_be_bytes(count_arr);
    let salt = base64::decode(salt)?;
    let hash = base64::decode(hash)?;

    let mut output = vec![0u8; hash.len()];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &salt, count, &mut output);

    // Be careful here - its important that the comparison be done using a fixed
    // time equality check. Otherwise an adversary that can measure how long
    // this step takes can learn about the hashed value which would allow them
    // to mount an offline brute force attack against the hashed password.
    if output.ct_eq(&hash).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(CheckError::HashMismatch)
    }
}
