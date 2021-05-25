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
//! ```
//! # #[cfg(feature = "password-hash")]
//! # {
//! use scrypt::{
//!     password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
//!     Scrypt
//! };
//! use rand_core::OsRng;
//!
//! let password = b"hunter42"; // Bad password; don't actually use!
//! let salt = SaltString::generate(&mut OsRng);
//!
//! // Hash password to PHC string ($scrypt$...)
//! let password_hash = Scrypt.hash_password_simple(password, salt.as_ref()).unwrap().to_string();
//!
//! // Verify password against PHC string
//! let parsed_hash = PasswordHash::new(&password_hash).unwrap();
//! assert!(Scrypt.verify_password(password, &parsed_hash).is_ok());
//! # }
//! ```
//!
//! # References
//! \[1\] - [C. Percival. Stronger Key Derivation Via Sequential
//! Memory-Hard Functions](http://www.tarsnap.com/scrypt/scrypt.pdf)

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;

/// Errors for `scrypt` operations.
pub mod errors;
mod params;
mod romix;
#[cfg(feature = "simple")]
mod simple;

#[cfg(feature = "simple")]
pub use password_hash;

pub use crate::params::Params;
#[cfg(feature = "simple")]
pub use crate::simple::{Scrypt, ALG_ID};

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
/// This function only uses a single thread (the current thread) for computation.
pub fn scrypt(
    password: &[u8],
    salt: &[u8],
    params: &Params,
    output: &mut [u8],
) -> Result<(), errors::InvalidOutputLen> {
    scrypt_log_f(password, salt, params, 0, 1, output)
}

/// The scrypt key derivation function that may use multiple threads.
///
/// # Arguments
/// - `password` - The password to process as a byte vector
/// - `salt` - The salt value to use as a byte vector
/// - `params` - The ScryptParams to use
/// - `max_memory` - The maximum amount of memory to use, in bytes. May use slightly more (on the order of hundreds of bytes).
/// - `num_threads` - The maximum number of threads to use.
/// - `output` - The resulting derived key is returned in this byte vector.
///   **WARNING: Make sure to compare this value in constant time!**
///
/// # Return
/// `Ok(())` if calculation is successful and `Err(InvalidOutputLen)` if
/// `output` does not satisfy the following condition:
/// `output.len() > 0 && output.len() <= (2^32 - 1) * 32`.
///
/// The parallel feature must be enabled for this function to use multiple threads.
/// Note that scrypt normally needs 2**log_n * 128 * r * min(num_threads, p) bytes for computation.
/// If max_memory is less than this, this implementation will automatically reduce memory usage.
/// Though this comes at the cost of increased computation.
/// (Note: It's always better to make this trade if it means using more CPU cores)
pub fn scrypt_parallel(
    password: &[u8],
    salt: &[u8],
    params: &Params,
    max_memory: usize,
    num_threads: usize,
    output: &mut [u8],
) -> Result<(), errors::InvalidOutputLen> {
    // The checks in the ScryptParams constructor guarantee
    // that the following is safe:
    let n: usize = 1 << params.log_n;
    let r128 = (params.r as usize) * 128;

    // No point in using more than p threads.
    let num_threads = num_threads.min(params.p as usize);

    // The optimal log_f is always the one that allows the most cores to run.
    // The increase in computation caused by increased log_f is always offset
    // by the increased core usage. Thus log_f can be calculated based on
    // num_threads and max_mem (assuming num_threads is less than or equal to
    // the number of cores).
    // So first we calculate how many blocks each thread can allocate.
    let mem_per_thread = max_memory / num_threads;
    let blocks_per_thread = mem_per_thread / r128;

    if blocks_per_thread == 0 {
        // TODO: Return error
        panic!("Not enough memory");
    }

    // Now log_f is calculated by determining how far right we need to shift n
    // to be less than or equal to blocks_per_thread.
    let possible_log_f = blocks_per_thread
        .leading_zeros()
        .saturating_sub(n.leading_zeros());

    // Rounding up.
    let log_f = if (n >> possible_log_f) > blocks_per_thread {
        // The checked_add should never fail.
        possible_log_f.checked_add(1).expect("overflow")
    } else {
        possible_log_f
    };

    scrypt_log_f(password, salt, params, log_f, num_threads, output)
}

/// The scrypt key derivation function that accepts the raw log_f parameter.
///
/// # Arguments
/// - `password` - The password to process as a byte vector
/// - `salt` - The salt value to use as a byte vector
/// - `params` - The ScryptParams to use
/// - `log_f` - A factor that reduces memory usage at the cost of increased computation; must be less than or equal to params.log_n
/// - `num_threads` - The maximum number of threads to use.
/// - `output` - The resulting derived key is returned in this byte vector.
///   **WARNING: Make sure to compare this value in constant time!**
///
/// # Return
/// `Ok(())` if calculation is successful and `Err(InvalidOutputLen)` if
/// `output` does not satisfy the following condition:
/// `output.len() > 0 && output.len() <= (2^32 - 1) * 32`.
#[doc(hidden)]
pub fn scrypt_log_f(
    password: &[u8],
    salt: &[u8],
    params: &Params,
    log_f: u32,
    num_threads: usize,
    output: &mut [u8],
) -> Result<(), errors::InvalidOutputLen> {
    // This check required by Scrypt:
    // check output.len() > 0 && output.len() <= (2^32 - 1) * 32
    if output.is_empty() || output.len() / 32 > 0xffff_ffff {
        return Err(errors::InvalidOutputLen);
    }

    // log_f must be less than or equal to log_n, or else V will be 0 bytes.
    assert!(log_f <= (params.log_n as u32));

    // The checks in the ScryptParams constructor guarantee
    // that the following is safe:
    let n = 1 << params.log_n;
    let r128 = (params.r as usize) * 128;
    let pr128 = (params.p as usize) * r128;
    let nr128 = n * r128;

    // B is a set of `p` blocks of data, each `r128` in length.
    let mut b = vec![0u8; pr128];
    pbkdf2::<Hmac<Sha256>>(&password, salt, 1, &mut b);

    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;

        // Each chunk of B can be operated on in parallel. Rayon is used to
        // distribute that work across the available threads.
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .expect("Unable to build rayon::ThreadPool");
        pool.install(|| {
            b.par_chunks_exact_mut(r128).for_each_init(
                || (vec![0u8; nr128 >> log_f], vec![0u8; r128 * 2]),
                |(v, t), chunk| romix::scrypt_ro_mix(chunk, v, t, n, log_f),
            );
        });
    }
    #[cfg(not(feature = "parallel"))]
    {
        let mut v = vec![0u8; nr128 >> log_f];
        let mut t = vec![0u8; r128 * 2];

        for chunk in b.chunks_exact_mut(r128) {
            romix::scrypt_ro_mix(chunk, &mut v, &mut t, n, log_f);
        }
    }

    pbkdf2::<Hmac<Sha256>>(&password, &b, 1, output);
    Ok(())
}
