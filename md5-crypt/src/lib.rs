//! Pure Rust implementation of the `MD5-crypt` password hash based on md5,
//! a legacy password hashing scheme supported by the [POSIX crypt C library][1].
//!
//! Password hashes using this algorithm start with `$1$` when encoded using the
//! [PHC string format][2].
//!
//! # Usage
//!
//! ```
//! # #[cfg(feature = "simple")]
//! # {
//! use md5_crypt::{md5_simple, md5_check};
//!
//! // Hash the password for storage
//! let hashed_password = md5_simple("Not so secure password")
//!     .expect("Should not fail");
//!
//! // Verifying a stored password
//! assert!(md5_check("Not so secure password", &hashed_password).is_ok());
//! # }
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/Crypt_(C)
//! [2]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

// TODO(tarcieri): heapless support
#[cfg(feature = "alloc")]
extern crate alloc;

mod b64;
mod defs;
mod errors;

pub use crate::{
    defs::{BLOCK_SIZE, PW_SIZE_MD5, SALT_MAX_LEN},
    errors::CryptError,
};

use md5::{Digest, Md5};

#[cfg(feature = "subtle")]
use crate::errors::CheckError;

#[cfg(feature = "simple")]
use {
    crate::defs::TAB,
    alloc::string::String,
    rand::{distributions::Distribution, thread_rng, Rng},
};

static MD5_SALT_PREFIX: &str = "$1$";

/// The MD5 crypt function returned as byte vector
///
/// If the provided hash is longer than defs::SALT_MAX_LEN character, it will
/// be stripped down to defs::SALT_MAX_LEN characters.
///
/// # Arguments
/// - `password` - The password to process as a byte vector
/// - `salt` - The salt value to use as a byte vector
///   **WARNING: Make sure to compare this value in constant time!**
///
/// # Returns
/// - `Ok(())` if calculation was successful
/// - `Err(errors::CryptError)` otherwise
pub fn md5_crypt(password: &[u8], salt: &[u8]) -> Result<[u8; BLOCK_SIZE], CryptError> {
    let salt_len = salt.len();
    let salt = match salt_len {
        0..=SALT_MAX_LEN => &salt[0..salt_len],
        _ => &salt[0..SALT_MAX_LEN],
    };

    let mut digest_b = Md5::default();
    digest_b.update(password);
    digest_b.update(salt);
    digest_b.update(password);
    let hash_b = digest_b.finalize();

    let mut digest_a = Md5::default();
    digest_a.update(password);
    digest_a.update(MD5_SALT_PREFIX);
    digest_a.update(salt);

    let mut pw_len = password.len();
    let rounds = pw_len / BLOCK_SIZE;
    for _ in 0..rounds {
        digest_a.update(hash_b);
    }

    // leftover password
    digest_a.update(&hash_b[..(pw_len - rounds * BLOCK_SIZE)]);

    while pw_len > 0 {
        match pw_len & 1 {
            0 => digest_a.update(&password[..1]),
            1 => digest_a.update([0u8]),
            _ => unreachable!(),
        }
        pw_len >>= 1;
    }

    let mut hash_a = digest_a.finalize();

    // Repeatedly run the collected hash value through MD5 to burn
    // CPU cycles
    for i in 0..1000_usize {
        // new hasher
        let mut hasher = Md5::default();

        // Add key or last result
        if (i & 1) != 0 {
            hasher.update(password);
        } else {
            hasher.update(hash_a);
        }

        // Add salt for numbers not divisible by 3
        if i % 3 != 0 {
            hasher.update(salt);
        }

        // Add key for numbers not divisible by 7
        if i % 7 != 0 {
            hasher.update(password);
        }

        // Add key or last result
        if (i & 1) != 0 {
            hasher.update(hash_a);
        } else {
            hasher.update(password);
        }

        // digest_c.clone_from_slice(&hasher.finalize());
        hash_a = hasher.finalize();
    }

    Ok(hash_a.into())
}

/// Same as md5_crypt except base64 representation will be returned.
///
/// # Arguments
/// - `password` - The password to process as a byte vector
/// - `salt` - The salt value to use as a byte vector
///   **WARNING: Make sure to compare this value in constant time!**
///
/// # Returns
/// - `Ok(())` if calculation was successful
/// - `Err(errors::CryptError)` otherwise
pub fn md5_crypt_b64(password: &[u8], salt: &[u8]) -> Result<[u8; PW_SIZE_MD5], CryptError> {
    let output = md5_crypt(password, salt)?;
    Ok(b64::encode_md5(&output))
}

/// Simple interface for generating a MD5 password hash.
///
/// The salt will be chosen randomly.
///
///  `$<ID>$<SALT>$<HASH>`
///
/// # Returns
/// - `Ok(String)` containing the full MD5 password hash format on success
/// - `Err(CryptError)` if something went wrong.
#[cfg(feature = "simple")]
#[cfg_attr(docsrs, doc(cfg(feature = "simple")))]
pub fn md5_simple(password: &str) -> Result<String, CryptError> {
    let rng = thread_rng();

    let salt: String = rng
        .sample_iter(&Md5CryptDistribution)
        .take(SALT_MAX_LEN)
        .collect();

    let out = md5_crypt(password.as_bytes(), salt.as_bytes())?;

    let mut result = String::new();
    result.push_str(MD5_SALT_PREFIX);
    result.push_str(&salt);
    result.push('$');
    let s = String::from_utf8(b64::encode_md5(&out).to_vec())?;
    result.push_str(&s);
    Ok(result)
}

/// Checks that given password matches provided hash.
///
/// # Arguments
/// - `password` - expected password
/// - `hashed_value` - the hashed value which should be used for checking,
/// should be of format mentioned `$1$<SALT>$<PWD>`.
///
/// # Return
/// `OK(())` if password matches otherwise Err(CheckError) in case of invalid
/// format or password mismatch.
#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "simple")))]
pub fn md5_check(password: &str, hashed_value: &str) -> Result<(), CheckError> {
    let mut iter = hashed_value.split('$');

    // Check that there are no characters before the first "$"
    if iter.next() != Some("") {
        return Err(CheckError::InvalidFormat("Should start with '$"));
    }

    if iter.next() != Some("1") {
        return Err(CheckError::InvalidFormat(
            "does not contain MD5 identifier: '$1$'",
        ));
    }

    let next = iter.next().ok_or(CheckError::InvalidFormat(
        "Does not contain a salt or hash string",
    ))?;

    let salt = next;

    let hash = iter
        .next()
        .ok_or(CheckError::InvalidFormat("Does not contain a hash string"))?;

    // Make sure there is no trailing data after the final "$"
    if iter.next().is_some() {
        return Err(CheckError::InvalidFormat("Trailing characters present"));
    }

    let output = md5_crypt(password.as_bytes(), salt.as_bytes()).map_err(CheckError::Crypt)?;

    let hash = b64::decode_md5(hash.as_bytes())?;

    use subtle::ConstantTimeEq;
    if output.ct_eq(&hash).into() {
        Ok(())
    } else {
        Err(CheckError::HashMismatch)
    }
}

#[cfg(feature = "simple")]
#[derive(Debug)]
struct Md5CryptDistribution;

#[cfg(feature = "simple")]
impl Distribution<char> for Md5CryptDistribution {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> char {
        const RANGE: u32 = 26 + 26 + 10 + 2; // 2 == "./"
        loop {
            let var = rng.next_u32() >> (32 - 6);
            if var < RANGE {
                return TAB[var as usize] as char;
            }
        }
    }
}
