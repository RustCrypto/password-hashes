#![no_std]
#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! # Usage
//!
#![cfg_attr(feature = "getrandom", doc = "```")]
#![cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
//! # fn main() -> password_hash::Result<()> {
//! // NOTE: example requires `getrandom` feature is enabled
//!
//! use sha_crypt::{SHA512_CRYPT, PasswordHasher, PasswordVerifier};
//!
//! let password = b"pleaseletmein"; // don't actually use this as a password!
//! let password_hash = SHA512_CRYPT.hash_password(password)?;
//! assert!(password_hash.as_str().starts_with("$6$"));
//!
//! // verify password is correct for the given hash
//! SHA512_CRYPT.verify_password(password, &password_hash)?;
//! # Ok(())
//! # }
//! ```

// TODO(tarcieri): heapless support
#[macro_use]
extern crate alloc;

mod consts;
mod errors;
mod params;
#[cfg(feature = "simple")]
mod simple;

pub use crate::{
    consts::{BLOCK_SIZE_SHA256, BLOCK_SIZE_SHA512},
    errors::Error,
    params::{ROUNDS_DEFAULT, ROUNDS_MAX, ROUNDS_MIN, Sha256Params, Sha512Params},
};

#[cfg(feature = "simple")]
pub use {
    crate::simple::{SHA256_CRYPT, SHA512_CRYPT, ShaCrypt},
    mcf::{self, PasswordHash},
    password_hash::{self, CustomizedPasswordHasher, PasswordHasher, PasswordVerifier},
};

use alloc::vec::Vec;
use sha2::{Digest, Sha256, Sha512};

/// The SHA512 crypt function returned as byte vector
///
/// If the provided hash is longer than defs::SALT_MAX_LEN character, it will
/// be stripped down to defs::SALT_MAX_LEN characters.
///
/// # Arguments
/// - `password` - The password to process as a byte vector
/// - `salt` - The salt value to use as a byte vector
/// - `params` - The Sha512Params to use
///   **WARNING: Make sure to compare this value in constant time!**
///
/// # Returns
/// - `Ok(())` if calculation was successful
/// - `Err(errors::CryptError)` otherwise
pub fn sha512_crypt(
    password: &[u8],
    salt: &[u8],
    params: &Sha512Params,
) -> [u8; BLOCK_SIZE_SHA512] {
    let pw_len = password.len();

    let salt_len = salt.len();
    let salt = match salt_len {
        0..=15 => &salt[0..salt_len],
        _ => &salt[0..16],
    };
    let salt_len = salt.len();

    let digest_a = sha512crypt_intermediate(password, salt);

    // 13.
    let mut hasher_alt = Sha512::default();

    // 14.
    for _ in 0..pw_len {
        hasher_alt.update(password);
    }

    // 15.
    let dp = hasher_alt.finalize();

    // 16.
    // Create byte sequence P.
    let p_vec = produce_byte_seq(pw_len, &dp);

    // 17.
    hasher_alt = Sha512::default();

    // 18.
    // For every character in the password add the entire password.
    for _ in 0..(16 + digest_a[0] as usize) {
        hasher_alt.update(salt);
    }

    // 19.
    // Finish the digest.
    let ds = hasher_alt.finalize();

    // 20.
    // Create byte sequence S.
    let s_vec = produce_byte_seq(salt_len, &ds);

    let mut digest_c = digest_a;
    // Repeatedly run the collected hash value through SHA512 to burn
    // CPU cycles
    for i in 0..params.rounds {
        // new hasher
        let mut hasher = Sha512::default();

        // Add key or last result
        if (i & 1) != 0 {
            hasher.update(&p_vec);
        } else {
            hasher.update(digest_c);
        }

        // Add salt for numbers not divisible by 3
        if i % 3 != 0 {
            hasher.update(&s_vec);
        }

        // Add key for numbers not divisible by 7
        if i % 7 != 0 {
            hasher.update(&p_vec);
        }

        // Add key or last result
        if (i & 1) != 0 {
            hasher.update(digest_c);
        } else {
            hasher.update(&p_vec);
        }

        digest_c.clone_from_slice(&hasher.finalize());
    }

    digest_c
}

/// The SHA256 crypt function returned as byte vector
///
/// If the provided hash is longer than defs::SALT_MAX_LEN character, it will
/// be stripped down to defs::SALT_MAX_LEN characters.
///
/// # Arguments
/// - `password` - The password to process as a byte vector
/// - `salt` - The salt value to use as a byte vector
/// - `params` - The Sha256Params to use
///   **WARNING: Make sure to compare this value in constant time!**
///
/// # Returns
/// - `Ok(())` if calculation was successful
/// - `Err(errors::CryptError)` otherwise
pub fn sha256_crypt(
    password: &[u8],
    salt: &[u8],
    params: &Sha256Params,
) -> [u8; BLOCK_SIZE_SHA256] {
    let pw_len = password.len();

    let salt_len = salt.len();
    let salt = match salt_len {
        0..=15 => &salt[0..salt_len],
        _ => &salt[0..16],
    };
    let salt_len = salt.len();

    let digest_a = sha256crypt_intermediate(password, salt);

    // 13.
    let mut hasher_alt = Sha256::default();

    // 14.
    for _ in 0..pw_len {
        hasher_alt.update(password);
    }

    // 15.
    let dp = hasher_alt.finalize();

    // 16.
    // Create byte sequence P.
    let p_vec = produce_byte_seq(pw_len, &dp);

    // 17.
    hasher_alt = Sha256::default();

    // 18.
    // For every character in the password add the entire password.
    for _ in 0..(16 + digest_a[0] as usize) {
        hasher_alt.update(salt);
    }

    // 19.
    // Finish the digest.
    let ds = hasher_alt.finalize();

    // 20.
    // Create byte sequence S.
    let s_vec = produce_byte_seq(salt_len, &ds);

    let mut digest_c = digest_a;
    // Repeatedly run the collected hash value through SHA256 to burn
    // CPU cycles
    for i in 0..params.rounds {
        // new hasher
        let mut hasher = Sha256::default();

        // Add key or last result
        if (i & 1) != 0 {
            hasher.update(&p_vec);
        } else {
            hasher.update(digest_c);
        }

        // Add salt for numbers not divisible by 3
        if i % 3 != 0 {
            hasher.update(&s_vec);
        }

        // Add key for numbers not divisible by 7
        if i % 7 != 0 {
            hasher.update(&p_vec);
        }

        // Add key or last result
        if (i & 1) != 0 {
            hasher.update(digest_c);
        } else {
            hasher.update(&p_vec);
        }

        digest_c.clone_from_slice(&hasher.finalize());
    }

    digest_c
}

fn produce_byte_seq(len: usize, fill_from: &[u8]) -> Vec<u8> {
    let bs = fill_from.len();
    let mut seq: Vec<u8> = vec![0; len];
    let mut offset: usize = 0;
    for _ in 0..(len / bs) {
        seq[offset..offset + bs].clone_from_slice(fill_from);
        offset += bs;
    }
    let from_slice = &fill_from[..(len % bs)];
    seq[offset..offset + (len % bs)].clone_from_slice(from_slice);
    seq
}

fn sha512crypt_intermediate(password: &[u8], salt: &[u8]) -> [u8; BLOCK_SIZE_SHA512] {
    let pw_len = password.len();

    let mut hasher = Sha512::default();
    hasher.update(password);
    hasher.update(salt);

    // 4.
    let mut hasher_alt = Sha512::default();
    // 5.
    hasher_alt.update(password);
    // 6.
    hasher_alt.update(salt);
    // 7.
    hasher_alt.update(password);
    // 8.
    let digest_b = hasher_alt.finalize();

    // 9.
    for _ in 0..(pw_len / BLOCK_SIZE_SHA512) {
        hasher.update(digest_b);
    }
    // 10.
    hasher.update(&digest_b[..(pw_len % BLOCK_SIZE_SHA512)]);

    // 11
    let mut n = pw_len;
    for _ in 0..pw_len {
        if n == 0 {
            break;
        }
        if (n & 1) != 0 {
            hasher.update(digest_b);
        } else {
            hasher.update(password);
        }
        n >>= 1;
    }

    // 12.
    hasher.finalize().as_slice().try_into().unwrap()
}

fn sha256crypt_intermediate(password: &[u8], salt: &[u8]) -> [u8; BLOCK_SIZE_SHA256] {
    let pw_len = password.len();

    let mut hasher = Sha256::default();
    hasher.update(password);
    hasher.update(salt);

    // 4.
    let mut hasher_alt = Sha256::default();
    // 5.
    hasher_alt.update(password);
    // 6.
    hasher_alt.update(salt);
    // 7.
    hasher_alt.update(password);
    // 8.
    let digest_b = hasher_alt.finalize();

    // 9.
    for _ in 0..(pw_len / BLOCK_SIZE_SHA256) {
        hasher.update(digest_b);
    }
    // 10.
    hasher.update(&digest_b[..(pw_len % BLOCK_SIZE_SHA256)]);

    // 11
    let mut n = pw_len;
    for _ in 0..pw_len {
        if n == 0 {
            break;
        }
        if (n & 1) != 0 {
            hasher.update(digest_b);
        } else {
            hasher.update(password);
        }
        n >>= 1;
    }

    // 12.
    hasher.finalize().as_slice().try_into().unwrap()
}
