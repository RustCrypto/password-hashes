#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_root_url = "https://docs.rs/balloon-hash/0.1.0"
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
//! balloon-hash = "0.1"
//! rand_core = { version = "0.6", features = ["std"] }
//! sha2 = "0.9"
//! ```
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
use core::marker::PhantomData;
use crypto_bigint::ArrayDecoding;
use digest::generic_array::GenericArray;
use digest::{Digest, FixedOutputReset};
#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
pub use password_hash::{self, PasswordHash, PasswordHasher, PasswordVerifier};
#[cfg(all(feature = "alloc", feature = "password-hash"))]
use {
    core::convert::TryFrom,
    password_hash::{Decimal, Ident, ParamsString, Salt},
};

/// Balloon context.
///
/// This is the primary type of this crate's API, and contains the following:
///
/// - Default set of [`Params`] to be used
/// - (Optional) Secret key a.k.a. "pepper" to be used
#[derive(Clone, Default)]
pub struct Balloon<'key, D: Digest + FixedOutputReset>
where
    GenericArray<u8, D::OutputSize>: ArrayDecoding,
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
    GenericArray<u8, D::OutputSize>: ArrayDecoding,
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
    pub fn hash(&self, pwd: &[u8], salt: &[u8]) -> Result<GenericArray<u8, D::OutputSize>> {
        #[cfg(not(feature = "parallel"))]
        let mut memory = alloc::vec![GenericArray::default(); self.params.s_cost.get() as usize];
        #[cfg(feature = "parallel")]
        let mut memory = alloc::vec![GenericArray::default(); (self.params.s_cost.get() * self.params.p_cost.get()) as usize];
        self.hash_with_memory(pwd, salt, &mut memory)
    }

    /// Hash a password and associated parameters.
    ///
    /// This method takes an explicit `memory_blocks` parameter which allows
    /// the caller to provide the backing storage for the algorithm's state:
    ///
    /// - Users with the `alloc` feature enabled can use [`Balloon::hash`]
    ///   to have it allocated for them.
    /// - `no_std` users on "heapless" targets can use an array of the [`GenericArray`] type
    ///   to stack allocate this buffer. It needs a minimum size of `s_cost` or `s_cost * p_cost`
    ///   with the `parallel` feature enabled.
    pub fn hash_with_memory(
        &self,
        pwd: &[u8],
        salt: &[u8],
        memory_blocks: &mut [GenericArray<u8, D::OutputSize>],
    ) -> Result<GenericArray<u8, D::OutputSize>> {
        match self.algorithm {
            Algorithm::Balloon => {
                balloon::balloon::<D>(pwd, salt, self.secret, self.params, memory_blocks)
            }
            Algorithm::BalloonM => {
                balloon::balloon_m::<D>(pwd, salt, self.secret, self.params, memory_blocks)
            }
        }
    }
}

#[cfg(all(feature = "alloc", feature = "password-hash"))]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl<D: Digest + FixedOutputReset> PasswordHasher for Balloon<'_, D>
where
    GenericArray<u8, D::OutputSize>: ArrayDecoding,
{
    type Params = Params;

    fn hash_password<'a, S>(
        &self,
        password: &[u8],
        salt: &'a S,
    ) -> password_hash::Result<PasswordHash<'a>>
    where
        S: AsRef<str> + ?Sized,
    {
        let salt = Salt::try_from(salt.as_ref())?;
        let mut salt_arr = [0u8; 64];
        let salt_bytes = salt.b64_decode(&mut salt_arr)?;

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

        Self::new(algorithm, params, self.secret).hash_password(password, salt.as_str())
    }
}

impl<'key, D: Digest + FixedOutputReset> From<Params> for Balloon<'key, D>
where
    GenericArray<u8, D::OutputSize>: ArrayDecoding,
{
    fn from(params: Params) -> Self {
        Self::new(Algorithm::default(), params, None)
    }
}

#[cfg(feature = "password-hash")]
#[test]
fn hash_simple_retains_configured_params() {
    use sha2::Sha256;

    /// Example password only: don't use this as a real password!!!
    const EXAMPLE_PASSWORD: &[u8] = b"hunter42";

    /// Example salt value. Don't use a static salt value!!!
    const EXAMPLE_SALT: &str = "examplesalt";

    // Non-default but valid parameters
    let t_cost = 4;
    let s_cost = 2048;
    let p_cost = 2;

    let params = Params::new(s_cost, t_cost, p_cost).unwrap();
    let hasher = Balloon::<Sha256>::new(Algorithm::default(), params, None);
    let hash = hasher
        .hash_password(EXAMPLE_PASSWORD, EXAMPLE_SALT)
        .unwrap();

    assert_eq!(hash.version.unwrap(), 1);

    for &(param, value) in &[("t", t_cost), ("s", s_cost), ("p", p_cost)] {
        assert_eq!(
            hash.params
                .get(param)
                .and_then(|p| p.decimal().ok())
                .unwrap(),
            value
        );
    }
}
