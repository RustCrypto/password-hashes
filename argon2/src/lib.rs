//! Pure Rust implementation of the [Argon2] password hashing function.
//!
//! # About
//!
//! Argon2 is a memory-hard [key derivation function] chosen as the winner of
//! the [Password Hashing Competition] in July 2015.
//!
//! It provides three algorithmic variants (chosen via the [`Algorithm`] enum):
//!
//! - **Argon2d**: maximizes resistance to GPU cracking attacks
//! - **Argon2i**: optimized to resist side-channel attacks
//! - **Argon2id**: (default) hybrid version combining both Argon2i and Argon2d
//!
//! Support is provided for embedded (i.e. `no_std`) environments, including
//! ones without `alloc` support.
//!
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
//! argon2 = "0.2"
//! rand_core = { version = "0.6", features = ["std"] }
//! ```
//!
//! The following example demonstrates the high-level password hashing API:
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # #[cfg(all(feature = "password-hash", feature = "std"))]
//! # {
//! use argon2::{
//!     password_hash::{
//!         rand_core::OsRng,
//!         PasswordHash, PasswordHasher, PasswordVerifier, SaltString
//!     },
//!     Argon2
//! };
//!
//! let password = b"hunter42"; // Bad password; don't actually use!
//! let salt = SaltString::generate(&mut OsRng);
//!
//! // Argon2 with default params (Argon2id v19)
//! let argon2 = Argon2::default();
//!
//! // Hash password to PHC string ($argon2id$v=19$...)
//! let password_hash = argon2.hash_password(password, &salt)?.to_string();
//!
//! // Verify password against PHC string
//! let parsed_hash = PasswordHash::new(&password_hash)?;
//! assert!(argon2.verify_password(password, &parsed_hash).is_ok());
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! [Argon2]: https://en.wikipedia.org/wiki/Argon2
//! [key derivation function]: https://en.wikipedia.org/wiki/Key_derivation_function
//! [Password Hashing Competition]: https://www.password-hashing.net/

#![no_std]
// TODO(tarcieri): safe parallel implementation
// See: https://github.com/RustCrypto/password-hashes/issues/154
#![cfg_attr(not(feature = "parallel"), forbid(unsafe_code))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_root_url = "https://docs.rs/argon2/0.2.4"
)]
#![warn(rust_2018_idioms, missing_docs)]

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod algorithm;
mod block;
mod error;
mod instance;
mod memory;
mod params;
mod version;

pub use crate::{
    algorithm::Algorithm,
    block::Block,
    error::{Error, Result},
    params::{Params, ParamsBuilder},
    version::Version,
};

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
pub use {
    crate::algorithm::{ARGON2D_IDENT, ARGON2ID_IDENT, ARGON2I_IDENT},
    password_hash::{self, PasswordHash, PasswordHasher, PasswordVerifier},
};

use crate::{
    instance::Instance,
    memory::{Memory, SYNC_POINTS},
};
use blake2::{digest, Blake2b, Digest};

#[cfg(all(feature = "alloc", feature = "password-hash"))]
use {
    core::convert::{TryFrom, TryInto},
    password_hash::{Decimal, Ident, Salt},
};

/// Maximum password length in bytes.
pub const MAX_PWD_LENGTH: usize = 0xFFFFFFFF;

/// Minimum and maximum associated data length in bytes.
pub const MAX_AD_LENGTH: usize = 0xFFFFFFFF;

/// Minimum and maximum salt length in bytes.
pub const MIN_SALT_LENGTH: usize = 8;

/// Maximum salt length in bytes.
pub const MAX_SALT_LENGTH: usize = 0xFFFFFFFF;

/// Maximum secret key length in bytes.
pub const MAX_SECRET_LENGTH: usize = 0xFFFFFFFF;

/// Argon2 context.
///
/// Holds the following Argon2 inputs:
///
/// - output array and its length,
/// - password and its length,
/// - salt and its length,
/// - secret and its length,
/// - associated data and its length,
/// - number of passes, amount of used memory (in KBytes, can be rounded up a bit)
/// - number of parallel threads that will be run.
///
/// All the parameters above affect the output hash value.
/// Additionally, two function pointers can be provided to allocate and
/// deallocate the memory (if NULL, memory will be allocated internally).
/// Also, three flags indicate whether to erase password, secret as soon as they
/// are pre-hashed (and thus not needed anymore), and the entire memory
///
/// Simplest situation: you have output array `out[8]`, password is stored in
/// `pwd[32]`, salt is stored in `salt[16]`, you do not have keys nor associated
/// data.
///
/// You need to spend 1 GB of RAM and you run 5 passes of Argon2d with
/// 4 parallel lanes.
///
/// You want to erase the password, but you're OK with last pass not being
/// erased.
// TODO(tarcieri): replace `Params`-related fields with an internally-stored struct
#[derive(Clone)]
pub struct Argon2<'key> {
    /// Algorithm to use
    algorithm: Algorithm,

    /// Version number
    version: Version,

    /// Algorithm parameters
    params: Params,

    /// Key array
    secret: Option<&'key [u8]>,
}

impl Default for Argon2<'_> {
    fn default() -> Self {
        Self::new(Algorithm::default(), Version::default(), Params::default())
    }
}

impl<'key> Argon2<'key> {
    /// Create a new Argon2 context.
    pub fn new(algorithm: Algorithm, version: Version, params: Params) -> Self {
        Self {
            algorithm,
            version,
            params,
            secret: None,
        }
    }

    /// Create a new Argon2 context.
    pub fn new_with_secret(
        secret: &'key [u8],
        algorithm: Algorithm,
        version: Version,
        params: Params,
    ) -> Result<Self> {
        if MAX_SECRET_LENGTH < secret.len() {
            return Err(Error::SecretTooLong);
        }

        Ok(Self {
            algorithm,
            version,
            params,
            secret: Some(secret),
        })
    }

    /// Hash a password and associated parameters into the provided output buffer.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn hash_password_into(
        &self,
        pwd: &[u8],
        salt: &[u8],
        ad: &[u8],
        out: &mut [u8],
    ) -> Result<()> {
        let mut blocks = vec![Block::default(); self.params.block_count()];
        self.hash_password_into_with_memory(pwd, salt, ad, out, &mut blocks)
    }

    /// Hash a password and associated parameters into the provided output buffer.
    ///
    /// This method takes an explicit `memory_blocks` parameter which allows
    /// the caller to provide the backing storage for the algorithm's state:
    ///
    /// - Users with the `alloc` feature enabled can use [`Argon2::hash_password_into`]
    ///   to have it allocated for them.
    /// - `no_std` users on "heapless" targets can use an array of the [`Block`] type
    ///   to stack allocate this buffer.
    pub fn hash_password_into_with_memory(
        &self,
        pwd: &[u8],
        salt: &[u8],
        ad: &[u8],
        out: &mut [u8],
        mut memory_blocks: impl AsMut<[Block]>,
    ) -> Result<()> {
        // Validate output length
        if out.len()
            < self
                .params
                .output_len()
                .unwrap_or(Params::MIN_OUTPUT_LENGTH)
        {
            return Err(Error::OutputTooShort);
        }

        if out.len()
            > self
                .params
                .output_len()
                .unwrap_or(Params::MAX_OUTPUT_LENGTH)
        {
            return Err(Error::OutputTooLong);
        }

        if pwd.len() > MAX_PWD_LENGTH {
            return Err(Error::PwdTooLong);
        }

        // Validate salt (required param)
        if salt.len() < MIN_SALT_LENGTH {
            return Err(Error::SaltTooShort);
        }

        if salt.len() > MAX_SALT_LENGTH {
            return Err(Error::SaltTooLong);
        }

        // Validate associated data (optional param)
        if ad.len() > MAX_AD_LENGTH {
            return Err(Error::AdTooLong);
        }

        // Hashing all inputs
        let initial_hash = self.initial_hash(pwd, salt, ad, out);

        let segment_length = self.params.segment_length();
        let block_count = self.params.block_count();
        let memory_blocks = memory_blocks
            .as_mut()
            .get_mut(..block_count)
            .ok_or(Error::MemoryTooLittle)?;

        let memory = Memory::new(memory_blocks, segment_length);
        Instance::hash(self, self.algorithm, initial_hash, memory, out)
    }

    /// Get default configured [`Params`].
    pub fn params(&self) -> &Params {
        &self.params
    }

    /// Hashes all the inputs into `blockhash[PREHASH_DIGEST_LENGTH]`.
    pub(crate) fn initial_hash(
        &self,
        pwd: &[u8],
        salt: &[u8],
        ad: &[u8],
        out: &[u8],
    ) -> digest::Output<Blake2b> {
        let mut digest = Blake2b::new();
        digest.update(&self.params.lanes().to_le_bytes());
        digest.update(&(out.len() as u32).to_le_bytes());
        digest.update(&self.params.m_cost().to_le_bytes());
        digest.update(&self.params.t_cost().to_le_bytes());
        digest.update(&self.version.to_le_bytes());
        digest.update(&self.algorithm.to_le_bytes());
        digest.update(&(pwd.len() as u32).to_le_bytes());
        digest.update(pwd);
        digest.update(&(salt.len() as u32).to_le_bytes());
        digest.update(salt);

        if let Some(secret) = &self.secret {
            digest.update(&(secret.len() as u32).to_le_bytes());
            digest.update(secret);
        } else {
            digest.update(0u32.to_le_bytes());
        }

        digest.update(&(ad.len() as u32).to_le_bytes());
        digest.update(ad);
        digest.finalize()
    }
}

#[cfg(all(feature = "alloc", feature = "password-hash"))]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl PasswordHasher for Argon2<'_> {
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

        // TODO(tarcieri): support the `data` parameter (i.e. associated data)
        let ad = b"";
        let output_len = self
            .params
            .output_len()
            .unwrap_or(Params::DEFAULT_OUTPUT_LENGTH);

        let output = password_hash::Output::init_with(output_len, |out| {
            Ok(self.hash_password_into(password, salt_bytes, ad, out)?)
        })?;

        Ok(PasswordHash {
            algorithm: self.algorithm.ident(),
            version: Some(self.version.into()),
            params: self.params.try_into()?,
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

        let version = version
            .map(Version::try_from)
            .transpose()?
            .unwrap_or_default();

        let salt = salt.into();

        Self {
            secret: self.secret,
            algorithm,
            version,
            params,
        }
        .hash_password(password, salt.as_str())
    }
}

impl<'key> From<Params> for Argon2<'key> {
    fn from(params: Params) -> Self {
        Self::new(Algorithm::default(), Version::default(), params)
    }
}

impl<'key> From<&Params> for Argon2<'key> {
    fn from(params: &Params) -> Self {
        Self::from(*params)
    }
}

#[cfg(all(test, feature = "alloc", feature = "password-hash"))]
mod tests {
    use crate::{Algorithm, Argon2, Params, PasswordHasher, Salt, Version};

    /// Example password only: don't use this as a real password!!!
    const EXAMPLE_PASSWORD: &[u8] = b"hunter42";

    /// Example salt value. Don't use a static salt value!!!
    const EXAMPLE_SALT: &str = "examplesalt";

    #[test]
    fn decoded_salt_too_short() {
        let argon2 = Argon2::default();

        // Too short after decoding
        let salt = Salt::new("somesalt").unwrap();

        let res =
            argon2.hash_password_customized(EXAMPLE_PASSWORD, None, None, Params::default(), salt);
        assert_eq!(
            res,
            Err(password_hash::Error::SaltInvalid(
                password_hash::errors::InvalidValue::TooShort
            ))
        );
    }

    #[test]
    fn hash_simple_retains_configured_params() {
        // Non-default but valid parameters
        let t_cost = 4;
        let m_cost = 2048;
        let p_cost = 2;
        let version = Version::V0x10;

        let params = Params::new(m_cost, t_cost, p_cost, None).unwrap();
        let hasher = Argon2::new(Algorithm::default(), version, params);
        let hash = hasher
            .hash_password(EXAMPLE_PASSWORD, EXAMPLE_SALT)
            .unwrap();

        assert_eq!(hash.version.unwrap(), version.into());

        for &(param, value) in &[("t", t_cost), ("m", m_cost), ("p", p_cost)] {
            assert_eq!(
                hash.params
                    .get(param)
                    .and_then(|p| p.decimal().ok())
                    .unwrap(),
                value
            );
        }
    }
}
