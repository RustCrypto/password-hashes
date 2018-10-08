//! This crate implements the Scrypt key derivation function as specified
//! in \[1\].
//!
//! If you are not using convinience functions `scrypt_check` and `scrypt_simple`
//! it's recommended to disable `scrypt` default features in your `Cargo.toml`:
//! ```toml
//! [dependencies]
//! scrypt = { version = "0.2", default-features = false }
//! ```
//!
//! # Usage
//!
//! ```
//! extern crate scrypt;
//!
//! # #[cfg(feature="include_simple")]
//! # fn main() {
//! use scrypt::{ScryptParams, scrypt_simple, scrypt_check};
//!
//! // First setup the ScryptParams arguments with:
//! // r = 8, p = 1, n = 32768 (log2(n) = 15)
//! let params = ScryptParams::new(15, 8, 1).unwrap();
//! // Hash the password for storage
//! let hashed_password = scrypt_simple("Not so secure password", &params)
//!     .expect("OS RNG should not fail");
//! // Verifying a stored password
//! assert!(scrypt_check("Not so secure password", &hashed_password).is_ok());
//! # }
//! # #[cfg(not(feature="include_simple"))]
//! fn main() {}
//! ```
//!
//! # References
//! \[1\] - [C. Percival. Stronger Key Derivation Via Sequential
//! Memory-Hard Functions](http://www.tarsnap.com/scrypt/scrypt.pdf)
#![doc(html_logo_url =
    "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
extern crate sha2;
extern crate pbkdf2;
extern crate hmac;
extern crate byteorder;
extern crate byte_tools;
#[cfg(feature="include_simple")]
extern crate subtle;
#[cfg(feature="include_simple")]
extern crate base64;
#[cfg(feature="include_simple")]
extern crate rand;

use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;

mod params;
mod romix;
/// Errors for `scrypt` operations.
pub mod errors;
#[cfg(feature="include_simple")]
mod simple;

#[cfg(feature="include_simple")]
pub use simple::{scrypt_simple, scrypt_check};
pub use params::ScryptParams;

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
/// `Ok(())` if calculation is succesfull and `Err(InvalidOutputLen)` if
/// `output` does not satisfy the following condition:
/// `output.len() > 0 && output.len() <= (2^32 - 1) * 32`.
pub fn scrypt(
    password: &[u8], salt: &[u8], params: &ScryptParams, output: &mut [u8]
) -> Result<(), errors::InvalidOutputLen> {
    // This check required by Scrypt:
    // check output.len() > 0 && output.len() <= (2^32 - 1) * 32
    if !(output.len() > 0 && output.len() / 32 <= 0xffffffff) {
        Err(errors::InvalidOutputLen)?;
    }

    // The checks in the ScryptParams constructor guarantee
    // that the following is safe:
    let n = 1 << params.log_n;
    let r128 = (params.r as usize) * 128;
    let pr128 = (params.p as usize) * r128;
    let nr128 = n * r128;

    let mut b = vec![0u8; pr128];
    pbkdf2::<Hmac<Sha256>>(&password, salt, 1, &mut b);

    let mut v = vec![0u8; nr128];
    let mut t = vec![0u8; r128];

    for chunk in &mut b.chunks_mut(r128) {
        romix::scrypt_ro_mix(chunk, &mut v, &mut t, n);
    }

    pbkdf2::<Hmac<Sha256>>(&password, &b, 1, output);
    Ok(())
}
