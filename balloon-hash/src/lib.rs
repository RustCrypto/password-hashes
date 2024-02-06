#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![warn(rust_2018_idioms, missing_docs)]

//! # Usage (simple with default params)
//!
//! Note: this example requires the `rand_core` crate with the `std` feature
//! enabled for `rand_core::OsRng` (embedded platforms can substitute their
//! own RNG)
//!
//! Add the following to your crate's `Cargo.toml` to import it:
//!
//! ```toml
//! [dependencies]
//! balloon-hash = "0.2"
//! rand_core = { version = "0.6", features = ["std"] }
//! sha2 = "0.9"
//! ```
//!
//! The `zeroize` crate feature will zeroize allocated memory created when
//! using the [`Balloon::hash`] function. It will do nothing when the `alloc`
//! crate feature is not active.
//!
//! The following example demonstrates the high-level password hashing API:
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # #[cfg(all(feature = "password-hash", feature = "std"))]
//! # {
//! use balloon_hash::{
//!     password_hash::{
//!         rand_core::OsRng,
//!         PasswordHash, PasswordHasher, PasswordVerifier, SaltString
//!     },
//!     Balloon
//! };
//! use sha2::Sha256;
//!
//! let password = b"hunter42"; // Bad password; don't actually use!
//! let salt = SaltString::generate(&mut OsRng);
//!
//! // Balloon with default params
//! let balloon = Balloon::<Sha256>::default();
//!
//! // Hash password to PHC string ($balloon$v=1$...)
//! let password_hash = balloon.hash_password(password, &salt)?.to_string();
//!
//! // Verify password against PHC string
//! let parsed_hash = PasswordHash::new(&password_hash)?;
//! assert!(balloon.verify_password(password, &parsed_hash).is_ok());
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! [Balloon]: https://en.wikipedia.org/wiki/Balloon_hashing

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod algorithm;
mod balloon;
mod error;
mod params;

pub use crate::{
    algorithm::Algorithm,
    error::{Error, Result},
    params::Params,
};

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
pub use password_hash::{self, PasswordHash, PasswordHasher, PasswordVerifier};

use core::marker::PhantomData;
use crypto_bigint::ArrayDecoding;
use digest::array::Array;
use digest::typenum::Unsigned;
use digest::{Digest, FixedOutputReset};

#[cfg(all(feature = "alloc", feature = "password-hash"))]
pub use password_hash::Salt;

#[cfg(all(feature = "alloc", feature = "password-hash"))]
use password_hash::{Decimal, Ident, ParamsString};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Balloon context.
///
/// This is the primary type of this crate's API, and contains the following:
///
/// - Default set of [`Params`] to be used
/// - (Optional) Secret key a.k.a. "pepper" to be used
#[derive(Clone, Default)]
pub struct Balloon<'key, D: Digest + FixedOutputReset>
where
    Array<u8, D::OutputSize>: ArrayDecoding,
{
    /// Storing which hash function is used
    pub digest: PhantomData<D>,
    /// Algorithm to use
    pub algorithm: Algorithm,
    /// Algorithm parameters
    pub params: Params,
    /// Key array
    pub secret: Option<&'key [u8]>,
}

impl<'key, D: Digest + FixedOutputReset> Balloon<'key, D>
where
    Array<u8, D::OutputSize>: ArrayDecoding,
{
    /// Create a new Balloon context.
    pub fn new(algorithm: Algorithm, params: Params, secret: Option<&'key [u8]>) -> Self {
        Self {
            digest: PhantomData,
            algorithm,
            params,
            secret,
        }
    }

    /// Hash a password and associated parameters.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn hash(&self, pwd: &[u8], salt: &[u8]) -> Result<Array<u8, D::OutputSize>> {
        let mut output = Array::default();
        self.hash_into(pwd, salt, &mut output)?;

        Ok(output)
    }

    /// Hash a password and associated parameters.
    ///
    /// The `output` has to have the same size as the hash output size: `D::OutputSize`.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn hash_into(&self, pwd: &[u8], salt: &[u8], output: &mut [u8]) -> Result<()> {
        #[cfg(not(feature = "parallel"))]
        let mut memory = alloc::vec![Array::default(); self.params.s_cost.get() as usize];
        #[cfg(feature = "parallel")]
        let mut memory = alloc::vec![Array::default(); (self.params.s_cost.get() * self.params.p_cost.get()) as usize];

        self.hash_into_with_memory(pwd, salt, &mut memory, output)?;
        #[cfg(feature = "zeroize")]
        memory.iter_mut().for_each(|block| block.zeroize());
        Ok(())
    }

    /// Hash a password and associated parameters.
    ///
    /// This method takes an explicit `memory_blocks` parameter which allows
    /// the caller to provide the backing storage for the algorithm's state:
    ///
    /// - Users with the `alloc` feature enabled can use [`Balloon::hash`]
    ///   to have it allocated for them.
    /// - `no_std` users on "heapless" targets can use an array of the [`Array`] type
    ///   to stack allocate this buffer. It needs a minimum size of `s_cost` or `s_cost * p_cost`
    ///   with the `parallel` crate feature enabled.
    pub fn hash_with_memory(
        &self,
        pwd: &[u8],
        salt: &[u8],
        memory_blocks: &mut [Array<u8, D::OutputSize>],
    ) -> Result<Array<u8, D::OutputSize>> {
        let mut output = Array::default();
        self.hash_into_with_memory(pwd, salt, memory_blocks, &mut output)?;

        Ok(output)
    }

    /// Hash a password and associated parameters into the provided `output` buffer.
    ///
    /// The `output` has to have the same size as the hash output size: `D::OutputSize`.
    ///
    /// See [`Balloon::hash_with_memory`] for more details.
    pub fn hash_into_with_memory(
        &self,
        pwd: &[u8],
        salt: &[u8],
        memory_blocks: &mut [Array<u8, D::OutputSize>],
        output: &mut [u8],
    ) -> Result<()> {
        let output = if output.len() == D::OutputSize::USIZE {
            Array::from_mut_slice(output)
        } else {
            return Err(Error::OutputSize {
                actual: output.len(),
                expected: D::OutputSize::USIZE,
            });
        };

        match self.algorithm {
            Algorithm::Balloon => {
                balloon::balloon::<D>(pwd, salt, self.secret, self.params, memory_blocks).map(
                    |hash| {
                        output.copy_from_slice(&hash);
                    },
                )
            }
            Algorithm::BalloonM => {
                balloon::balloon_m::<D>(pwd, salt, self.secret, self.params, memory_blocks, output)
            }
        }
    }
}

#[cfg(all(feature = "alloc", feature = "password-hash"))]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl<D: Digest + FixedOutputReset> PasswordHasher for Balloon<'_, D>
where
    Array<u8, D::OutputSize>: ArrayDecoding,
{
    type Params = Params;

    fn hash_password<'a>(
        &self,
        password: &[u8],
        salt: impl Into<Salt<'a>>,
    ) -> password_hash::Result<PasswordHash<'a>> {
        let salt = salt.into();
        let mut salt_arr = [0u8; 64];
        let salt_bytes = salt.decode_b64(&mut salt_arr)?;
        let output = password_hash::Output::new(&self.hash(password, salt_bytes)?)?;

        Ok(PasswordHash {
            algorithm: self.algorithm.ident(),
            version: Some(1),
            params: ParamsString::try_from(&self.params)?,
            salt: Some(salt),
            hash: Some(output),
        })
    }

    fn hash_password_customized<'a>(
        &self,
        password: &[u8],
        alg_id: Option<Ident<'a>>,
        version: Option<Decimal>,
        params: Params,
        salt: impl Into<Salt<'a>>,
    ) -> password_hash::Result<PasswordHash<'a>> {
        let algorithm = alg_id
            .map(Algorithm::try_from)
            .transpose()?
            .unwrap_or_default();

        if let Some(version) = version {
            if version != 1 {
                return Err(password_hash::Error::Version);
            }
        }

        let salt = salt.into();

        Self::new(algorithm, params, self.secret).hash_password(password, salt)
    }
}

impl<'key, D: Digest + FixedOutputReset> From<Params> for Balloon<'key, D>
where
    Array<u8, D::OutputSize>: ArrayDecoding,
{
    fn from(params: Params) -> Self {
        Self::new(Algorithm::default(), params, None)
    }
}
