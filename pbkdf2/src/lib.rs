#![no_std]
#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]

//! # Examples
//!
//! PBKDF2 is defined in terms of a keyed pseudo-random function (PRF).
//! The most commonly used PRF for this purpose is HMAC. In such cases
//! you can use [`pbkdf2_hmac`] and [`pbkdf2_hmac_array`] functions.
//! The former accepts a byte slice which gets filled with generated key,
//! while the latter returns an array with generated key of requested length.
//!
//! Note that it is not recommended to generate keys using PBKDF2 that exceed
//! the output size of the PRF (equal to the hash size in the case of HMAC).
//! If you need to generate a large amount of cryptographic material,
//! consider using a separate [key derivation function][KDF].
//!
//! [KDF]: https://github.com/RustCrypto/KDFs
//!
//! ```
//! # #[cfg(feature = "hmac")] {
//! use hex_literal::hex;
//! use pbkdf2::{pbkdf2_hmac, pbkdf2_hmac_array};
//! use sha2::Sha256;
//!
//! let password = b"password";
//! let salt = b"salt";
//! // number of iterations
//! let n = 600_000;
//! // Expected value of generated key
//! let expected = hex!("669cfe52482116fda1aa2cbe409b2f56c8e45637");
//!
//! let mut key1 = [0u8; 20];
//! pbkdf2_hmac::<Sha256>(password, salt, n, &mut key1);
//! assert_eq!(key1, expected);
//!
//! let key2 = pbkdf2_hmac_array::<Sha256, 20>(password, salt, n);
//! assert_eq!(key2, expected);
//! # }
//! ```
//!
//! If you want to use a different PRF, then you can use [`pbkdf2`] and [`pbkdf2_array`] functions.
//!
//! This crates also provides the high-level password-hashing API through
//! the [`Pbkdf2`] struct and traits defined in the
//! [`password-hash`][password_hash] crate.
//!
//! Add the following to your crate's `Cargo.toml` to import it:
//!
//! ```toml
//! [dependencies]
//! pbkdf2 = { version = "0.12", features = ["password-hash"] }
//! rand_core = { version = "0.6", features = ["std"] }
//! ```
//!
//! The following example demonstrates the high-level password hashing API:
//!
#![cfg_attr(feature = "password-hash", doc = "```")]
#![cfg_attr(not(feature = "password-hash"), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! // NOTE: example requires `getrandom` feature is enabled
//!
//! use pbkdf2::{
//!     password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
//!     Pbkdf2
//! };
//!
//! let pbkdf2 = Pbkdf2::new(); // Uses `Params::RECOMMENDED`
//! let password = b"hunter42"; // Bad password; don't actually use!
//!
//! // Hash password to PHC string ($pbkdf2-sha256$...)
//! let password_hash = pbkdf2.hash_password(password)?.to_string();
//!
//! // Verify password against PHC string
//! let parsed_hash = PasswordHash::new(&password_hash)?;
//! assert!(pbkdf2.verify_password(password, &parsed_hash).is_ok());
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "password-hash")]
extern crate alloc;

#[cfg(feature = "password-hash")]
pub use password_hash;

#[cfg(feature = "password-hash")]
mod algorithm;
#[cfg(feature = "password-hash")]
mod params;
#[cfg(feature = "password-hash")]
mod phc;

#[cfg(feature = "hmac")]
pub use hmac;

#[cfg(feature = "password-hash")]
pub use crate::{algorithm::Algorithm, params::Params, phc::Pbkdf2};

use digest::{FixedOutput, InvalidLength, KeyInit, Update, typenum::Unsigned};

#[cfg(feature = "hmac")]
use hmac::EagerHash;

#[inline(always)]
fn xor(res: &mut [u8], salt: &[u8]) {
    debug_assert!(salt.len() >= res.len(), "length mismatch in xor");
    res.iter_mut().zip(salt.iter()).for_each(|(a, b)| *a ^= b);
}

#[inline(always)]
fn pbkdf2_body<PRF>(i: u32, chunk: &mut [u8], prf: &PRF, salt: &[u8], rounds: u32)
where
    PRF: Update + FixedOutput + Clone,
{
    for v in chunk.iter_mut() {
        *v = 0;
    }

    let mut salt = {
        let mut prfc = prf.clone();
        prfc.update(salt);
        prfc.update(&(i + 1).to_be_bytes());

        let salt = prfc.finalize_fixed();
        xor(chunk, &salt);
        salt
    };

    for _ in 1..rounds {
        let mut prfc = prf.clone();
        prfc.update(&salt);
        salt = prfc.finalize_fixed();

        xor(chunk, &salt);
    }
}

/// Generic implementation of PBKDF2 algorithm which accepts an arbitrary keyed PRF.
///
/// ```
/// use hex_literal::hex;
/// use pbkdf2::pbkdf2;
/// use hmac::Hmac;
/// use sha2::Sha256;
///
/// let mut buf = [0u8; 20];
/// pbkdf2::<Hmac<Sha256>>(b"password", b"salt", 600_000, &mut buf)
///     .expect("HMAC can be initialized with any key length");
/// assert_eq!(buf, hex!("669cfe52482116fda1aa2cbe409b2f56c8e45637"));
/// ```
#[inline]
pub fn pbkdf2<PRF>(
    password: &[u8],
    salt: &[u8],
    rounds: u32,
    res: &mut [u8],
) -> Result<(), InvalidLength>
where
    PRF: KeyInit + Update + FixedOutput + Clone + Sync,
{
    let n = PRF::OutputSize::to_usize();
    let prf = PRF::new_from_slice(password)?;

    for (i, chunk) in res.chunks_mut(n).enumerate() {
        pbkdf2_body(i as u32, chunk, &prf, salt, rounds);
    }

    Ok(())
}

/// A variant of the [`pbkdf2`] function which returns an array instead of filling an input slice.
///
/// ```
/// use hex_literal::hex;
/// use pbkdf2::pbkdf2_array;
/// use hmac::Hmac;
/// use sha2::Sha256;
///
/// let res = pbkdf2_array::<Hmac<Sha256>, 20>(b"password", b"salt", 600_000)
///     .expect("HMAC can be initialized with any key length");
/// assert_eq!(res, hex!("669cfe52482116fda1aa2cbe409b2f56c8e45637"));
/// ```
#[inline]
pub fn pbkdf2_array<PRF, const N: usize>(
    password: &[u8],
    salt: &[u8],
    rounds: u32,
) -> Result<[u8; N], InvalidLength>
where
    PRF: KeyInit + Update + FixedOutput + Clone + Sync,
{
    let mut buf = [0u8; N];
    pbkdf2::<PRF>(password, salt, rounds, &mut buf).map(|()| buf)
}

/// A variant of the [`pbkdf2`] function which uses HMAC for PRF.
///
/// It's generic over (eager) hash functions.
///
/// ```
/// use hex_literal::hex;
/// use pbkdf2::pbkdf2_hmac;
/// use sha2::Sha256;
///
/// let mut buf = [0u8; 20];
/// pbkdf2_hmac::<Sha256>(b"password", b"salt", 600_000, &mut buf);
/// assert_eq!(buf, hex!("669cfe52482116fda1aa2cbe409b2f56c8e45637"));
/// ```
#[cfg(feature = "hmac")]
pub fn pbkdf2_hmac<D>(password: &[u8], salt: &[u8], rounds: u32, res: &mut [u8])
where
    D: EagerHash<Core: Sync>,
{
    crate::pbkdf2::<hmac::Hmac<D>>(password, salt, rounds, res)
        .expect("HMAC can be initialized with any key length");
}

/// A variant of the [`pbkdf2_hmac`] function which returns an array
/// instead of filling an input slice.
///
/// ```
/// use hex_literal::hex;
/// use pbkdf2::pbkdf2_hmac_array;
/// use sha2::Sha256;
///
/// assert_eq!(
///     pbkdf2_hmac_array::<Sha256, 20>(b"password", b"salt", 600_000),
///     hex!("669cfe52482116fda1aa2cbe409b2f56c8e45637"),
/// );
/// ```
#[cfg(feature = "hmac")]
pub fn pbkdf2_hmac_array<D, const N: usize>(password: &[u8], salt: &[u8], rounds: u32) -> [u8; N]
where
    D: EagerHash<Core: Sync>,
{
    let mut buf = [0u8; N];
    pbkdf2_hmac::<D>(password, salt, rounds, &mut buf);
    buf
}
