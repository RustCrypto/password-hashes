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
//! ## Low-level API
//!
//! This API operates directly on byte slices:
//!
#![cfg_attr(feature = "sha2", doc = "```")]
#![cfg_attr(not(feature = "sha2"), doc = "```ignore")]
//! // NOTE: example requires `getrandom` feature is enabled
//!
//! use hex_literal::hex;
//! use pbkdf2::{pbkdf2_hmac, pbkdf2_hmac_array, sha2::Sha256};
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
//! ```
//!
//! If you want to use a different PRF, then you can use [`pbkdf2`] and [`pbkdf2_array`] functions.
//!
//! ## PHC string API
//!
//! This crate can produce and verify password hash strings encoded in the Password Hashing
//! Competition (PHC) string format using the [`Pbkdf2`] struct.
//!
//! The following example demonstrates the high-level password hashing API:
//!
#![cfg_attr(all(feature = "getrandom", feature = "phc"), doc = "```")]
#![cfg_attr(not(all(feature = "getrandom", feature = "phc")), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! // NOTE: example requires `getrandom` feature is enabled
//!
//! use pbkdf2::{
//!     password_hash::{PasswordHasher, PasswordVerifier},
//!     phc::PasswordHash,
//!     Pbkdf2
//! };
//!
//! let pbkdf2 = Pbkdf2::default(); // Uses `Algorithm::default()` and `Params::RECOMMENDED`
//! let password = b"hunter2"; // Bad password; don't actually use!
//!
//! // Hash password to PHC string ($pbkdf2-sha256$...)
//! let pwhash: PasswordHash = pbkdf2.hash_password(password)?;
//! let pwhash_string = pwhash.to_string();
//!
//! // Verify password against PHC string
//! let parsed_hash = PasswordHash::new(&pwhash_string)?;
//! pbkdf2.verify_password(password, &parsed_hash)?;
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "mcf")]
pub mod mcf;
#[cfg(feature = "phc")]
pub mod phc;

#[cfg(any(feature = "sha1", feature = "sha2"))]
mod algorithm;
#[cfg(any(feature = "sha1", feature = "sha2"))]
mod params;

#[cfg(any(feature = "sha1", feature = "sha2"))]
pub use crate::{algorithm::Algorithm, params::Params};
#[cfg(feature = "hmac")]
pub use hmac;
#[cfg(any(feature = "mcf", feature = "phc"))]
pub use password_hash;
#[cfg(any(feature = "mcf", feature = "phc"))]
pub use password_hash::{PasswordHasher, PasswordVerifier};
#[cfg(feature = "sha1")]
pub use sha1;
#[cfg(feature = "sha2")]
pub use sha2;

use digest::{FixedOutput, InvalidLength, KeyInit, Update, typenum::Unsigned};

#[cfg(feature = "hmac")]
use hmac::EagerHash;
#[cfg(feature = "kdf")]
use kdf::{Kdf, Pbkdf};

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
#[cfg_attr(feature = "sha2", doc = "```")]
#[cfg_attr(not(feature = "sha2"), doc = "```ignore")]
/// use hex_literal::hex;
/// use pbkdf2::{pbkdf2, hmac::Hmac, sha2::Sha256};
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
#[cfg_attr(feature = "sha2", doc = "```")]
#[cfg_attr(not(feature = "sha2"), doc = "```ignore")]
/// use hex_literal::hex;
/// use pbkdf2::{pbkdf2_array, hmac::Hmac, sha2::Sha256};
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
#[cfg_attr(feature = "sha2", doc = "```")]
#[cfg_attr(not(feature = "sha2"), doc = "```ignore")]
/// use hex_literal::hex;
/// use pbkdf2::{pbkdf2_hmac, sha2::Sha256};
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
    pbkdf2::<hmac::Hmac<D>>(password, salt, rounds, res)
        .expect("HMAC can be initialized with any key length");
}

/// A variant of the [`pbkdf2_hmac`] function which returns an array
/// instead of filling an input slice.
///
#[cfg_attr(feature = "sha2", doc = "```")]
#[cfg_attr(not(feature = "sha2"), doc = "```ignore")]
/// use hex_literal::hex;
/// use pbkdf2::{pbkdf2_hmac_array, sha2::Sha256};
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

/// API for using [`pbkdf2_hmac`] which supports the [`Algorithm`] and [`Params`] types and with
/// it runtime selection of which algorithm to use.
///
#[cfg_attr(feature = "sha2", doc = "```")]
#[cfg_attr(not(feature = "sha2"), doc = "```ignore")]
/// use hex_literal::hex;
/// use pbkdf2::pbkdf2_hmac_with_params;
///
/// let algorithm = pbkdf2::Algorithm::Pbkdf2Sha256;
/// let params = pbkdf2::Params::default();
///
/// let mut buf = [0u8; 32];
/// pbkdf2_hmac_with_params(b"password", b"salt", algorithm, params, &mut buf);
/// assert_eq!(buf, hex!("669cfe52482116fda1aa2cbe409b2f56c8e4563752b7a28f6eaab614ee005178"));
/// ```
#[cfg(any(feature = "sha1", feature = "sha2"))]
pub fn pbkdf2_hmac_with_params(
    password: &[u8],
    salt: &[u8],
    algorithm: Algorithm,
    params: Params,
    out: &mut [u8],
) {
    let f = match algorithm {
        #[cfg(feature = "sha1")]
        Algorithm::Pbkdf2Sha1 => pbkdf2_hmac::<sha1::Sha1>,
        #[cfg(feature = "sha2")]
        Algorithm::Pbkdf2Sha256 => pbkdf2_hmac::<sha2::Sha256>,
        #[cfg(feature = "sha2")]
        Algorithm::Pbkdf2Sha512 => pbkdf2_hmac::<sha2::Sha512>,
    };

    f(password, salt, params.rounds(), out);
}

/// PBKDF2 type for use with the [`PasswordHasher`] and [`PasswordVerifier`] traits, which
/// implements support for password hash strings.
///
/// Supports the following password hash string formats, gated under the following crate features:
/// - `mcf`: support for the Modular Crypt Format
/// - `phc`: support for the Password Hashing Competition string format
#[cfg(any(feature = "sha1", feature = "sha2"))]
#[cfg_attr(feature = "sha2", derive(Default))]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Pbkdf2 {
    /// Algorithm to use
    algorithm: Algorithm,

    /// Default parameters to use.
    params: Params,
}

#[cfg(feature = "sha2")]
impl Pbkdf2 {
    /// PBKDF2 configured with SHA-256 as the default.
    pub const SHA256: Self = Self::new(Algorithm::Pbkdf2Sha256, Params::RECOMMENDED);

    /// PBKDF2 configured with SHA-512 as the default.
    pub const SHA512: Self = Self::new(Algorithm::Pbkdf2Sha512, Params::RECOMMENDED);
}

#[cfg(any(feature = "sha1", feature = "sha2"))]
impl Pbkdf2 {
    /// Initialize [`Pbkdf2`] with default parameters.
    pub const fn new(algorithm: Algorithm, params: Params) -> Self {
        Self { algorithm, params }
    }

    /// Hash password into the given output buffer using the configured params.
    pub fn hash_password_into(&self, password: &[u8], salt: &[u8], out: &mut [u8]) {
        pbkdf2_hmac_with_params(password, salt, self.algorithm, self.params, out);
    }
}

#[cfg(any(feature = "sha1", feature = "sha2"))]
impl From<Algorithm> for Pbkdf2 {
    fn from(algorithm: Algorithm) -> Self {
        Self {
            algorithm,
            params: Params::default(),
        }
    }
}

#[cfg(feature = "sha2")]
impl From<Params> for Pbkdf2 {
    fn from(params: Params) -> Self {
        Self {
            algorithm: Algorithm::default(),
            params,
        }
    }
}

#[cfg(feature = "kdf")]
impl Kdf for Pbkdf2 {
    fn derive_key(&self, password: &[u8], salt: &[u8], out: &mut [u8]) -> kdf::Result<()> {
        self.hash_password_into(password, salt, out);
        Ok(())
    }
}

#[cfg(feature = "kdf")]
impl Pbkdf for Pbkdf2 {}
