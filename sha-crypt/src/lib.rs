//! Pure Rust implementation of the [`SHA-crypt` password hash based on SHA-512][1],
//! a legacy password hashing scheme supported by the [POSIX crypt C library][2].
//!
//! Password hashes using this algorithm start with `$6$` when encoded using the
//! [PHC string format][3].
//!
//! # Usage
//!
//! ```
//! # #[cfg(feature = "simple")]
//! # {
//! use sha_crypt::{Sha512Params, sha512_simple, sha512_check};
//!
//! // First setup the Sha512Params arguments with:
//! // rounds = 10_000
//! let params = Sha512Params::new(10_000).expect("RandomError!");
//!
//! // Hash the password for storage
//! let hashed_password = sha512_simple("Not so secure password", &params);
//!
//! // Verifying a stored password
//! assert!(sha512_check("Not so secure password", &hashed_password).is_ok());
//! # }
//! ```
//!
//! [1]: https://www.akkadia.org/drepper/SHA-crypt.txt
//! [2]: https://en.wikipedia.org/wiki/Crypt_(C)
//! [3]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

// TODO(tarcieri): heapless support
#[macro_use]
extern crate alloc;

mod consts;
mod errors;
mod params;
mod simple;

pub use crate::{
    consts::{BLOCK_SIZE_SHA256, BLOCK_SIZE_SHA512},
    errors::CryptError,
    params::{ROUNDS_DEFAULT, ROUNDS_MAX, ROUNDS_MIN, Sha256Params, Sha512Params},
};

#[cfg(feature = "simple")]
pub use crate::simple::{sha256_check, sha256_simple, sha512_check, sha512_simple};

use alloc::{string::String, vec::Vec};
use base64ct::{Base64ShaCrypt, Encoding};
use sha2::{Digest, Sha256, Sha512};

#[cfg(feature = "simple")]
pub use crate::errors::{CheckError, DecodeError};

use crate::consts::{MAP_SHA256, MAP_SHA512};

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

/// Same as sha512_crypt except base64 representation will be returned.
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
pub fn sha512_crypt_b64(password: &[u8], salt: &[u8], params: &Sha512Params) -> String {
    let output = sha512_crypt(password, salt, params);

    let mut transposed = [0u8; BLOCK_SIZE_SHA512];
    for (i, &ti) in MAP_SHA512.iter().enumerate() {
        transposed[i] = output[ti as usize];
    }

    Base64ShaCrypt::encode_string(&transposed)
}

/// Same as sha256_crypt except base64 representation will be returned.
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
pub fn sha256_crypt_b64(password: &[u8], salt: &[u8], params: &Sha256Params) -> String {
    let output = sha256_crypt(password, salt, params);

    let mut transposed = [0u8; BLOCK_SIZE_SHA256];
    for (i, &ti) in MAP_SHA256.iter().enumerate() {
        transposed[i] = output[ti as usize];
    }

    Base64ShaCrypt::encode_string(&transposed)
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
