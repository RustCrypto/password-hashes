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
//! - **Argon2id**: (default) hybrid version
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
//! argon2 = "0.1"
//! rand_core = { version = "0.6", features = ["std"] }
//! ```
//!
//! The following example demonstrates the high-level password hashing API:
//!
//! ```
//! # #[cfg(feature = "password-hash")]
//! # {
//! use argon2::{
//!     password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
//!     Argon2
//! };
//! use rand_core::OsRng;
//!
//! let password = b"hunter42"; // Bad password; don't actually use!
//! let salt = SaltString::generate(&mut OsRng);
//!
//! // Argon2 with default params (Argon2id v19)
//! let argon2 = Argon2::default();
//!
//! // Hash password to PHC string ($argon2id$v=19$...)
//! let password_hash = argon2.hash_password_simple(password, salt.as_ref()).unwrap().to_string();
//!
//! // Verify password against PHC string
//! let parsed_hash = PasswordHash::new(&password_hash).unwrap();
//! assert!(argon2.verify_password(password, &parsed_hash).is_ok());
//! # }
//! ```
//!
//! # Notes
//!
//! Multithreading has not yet been implemented.
//!
//! Increasing the parallelism factor will still compute the correct results,
//! but there will be no associated performance improvement.
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
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(rust_2018_idioms, missing_docs)]

#[macro_use]
extern crate alloc;

mod block;
mod error;
mod instance;
mod memory;
mod version;

#[cfg(feature = "password-hash")]
mod params;

pub use crate::{error::Error, version::Version};

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
pub use {
    params::Params,
    password_hash::{self, PasswordHash, PasswordHasher, PasswordVerifier},
};

use crate::{
    block::Block,
    instance::Instance,
    memory::{Memory, SYNC_POINTS},
};
use blake2::{digest, Blake2b, Digest};
use core::{
    fmt::{self, Display},
    str::FromStr,
};

#[cfg(feature = "password-hash")]
use {
    core::convert::{TryFrom, TryInto},
    password_hash::{Ident, Salt},
};

/// Minimum and maximum number of lanes (degree of parallelism)
pub const MIN_LANES: u32 = 1;

/// Minimum and maximum number of lanes (degree of parallelism)
pub const MAX_LANES: u32 = 0xFFFFFF;

/// Minimum and maximum number of threads
pub const MIN_THREADS: u32 = 1;

/// Minimum and maximum number of threads
pub const MAX_THREADS: u32 = 0xFFFFFF;

/// Minimum digest size in bytes
pub const MIN_OUTLEN: usize = 4;

/// Maximum digest size in bytes
pub const MAX_OUTLEN: usize = 0xFFFFFFFF;

/// Minimum number of memory blocks.
pub const MIN_MEMORY: u32 = 2 * SYNC_POINTS; // 2 blocks per slice

/// Maximum number of memory blocks.
pub const MAX_MEMORY: u32 = 0x0FFFFFFF;

/// Minimum number of passes
pub const MIN_TIME: u32 = 1;

/// Maximum number of passes
pub const MAX_TIME: u32 = 0xFFFFFFFF;

/// Maximum password length in bytes
pub const MAX_PWD_LENGTH: usize = 0xFFFFFFFF;

/// Minimum and maximum associated data length in bytes
pub const MAX_AD_LENGTH: usize = 0xFFFFFFFF;

/// Minimum and maximum salt length in bytes
pub const MIN_SALT_LENGTH: usize = 8;

/// Maximum salt length in bytes
pub const MAX_SALT_LENGTH: usize = 0xFFFFFFFF;

/// Maximum key length in bytes
pub const MAX_SECRET: usize = 0xFFFFFFFF;

/// Argon2d algorithm identifier
#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
pub const ARGON2D_IDENT: Ident<'_> = Ident::new("argon2d");

/// Argon2i algorithm identifier
#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
pub const ARGON2I_IDENT: Ident<'_> = Ident::new("argon2i");

/// Argon2id algorithm identifier
#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
pub const ARGON2ID_IDENT: Ident<'_> = Ident::new("argon2id");

/// Argon2 primitive type: variants of the algorithm.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Algorithm {
    /// Optimizes against GPU cracking attacks but vulnerable to side-channels.
    ///
    /// Accesses the memory array in a password dependent order, reducing the
    /// possibility of time–memory tradeoff (TMTO) attacks.
    Argon2d = 0,

    /// Optimized to resist side-channel attacks.
    ///
    /// Accesses the memory array in a password independent order, increasing the
    /// possibility of time-memory tradeoff (TMTO) attacks.
    Argon2i = 1,

    /// Hybrid that mixes Argon2i and Argon2d passes (*default*).
    ///
    /// Uses the Argon2i approach for the first half pass over memory and
    /// Argon2d approach for subsequent passes. This effectively places it in
    /// the "middle" between the other two: it doesn't provide as good
    /// TMTO/GPU cracking resistance as Argon2d, nor as good of side-channel
    /// resistance as Argon2i, but overall provides the most well-rounded
    /// approach to both classes of attacks.
    Argon2id = 2,
}

impl Default for Algorithm {
    fn default() -> Algorithm {
        Algorithm::Argon2id
    }
}

impl Algorithm {
    /// Parse an [`Algorithm`] from the provided string.
    pub fn new(id: impl AsRef<str>) -> Result<Self, Error> {
        id.as_ref().parse()
    }

    /// Get the identifier string for this PBKDF2 [`Algorithm`].
    pub fn as_str(&self) -> &str {
        match self {
            Algorithm::Argon2d => "argon2d",
            Algorithm::Argon2i => "argon2i",
            Algorithm::Argon2id => "argon2id",
        }
    }

    /// Get the [`Ident`] that corresponds to this Argon2 [`Algorithm`].
    #[cfg(feature = "password-hash")]
    #[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
    pub fn ident(&self) -> Ident<'static> {
        match self {
            Algorithm::Argon2d => ARGON2D_IDENT,
            Algorithm::Argon2i => ARGON2I_IDENT,
            Algorithm::Argon2id => ARGON2ID_IDENT,
        }
    }

    /// Serialize primitive type as little endian bytes
    fn to_le_bytes(self) -> [u8; 4] {
        (self as u32).to_le_bytes()
    }
}

impl AsRef<str> for Algorithm {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Algorithm, Error> {
        match s {
            "argon2d" => Ok(Algorithm::Argon2d),
            "argon2i" => Ok(Algorithm::Argon2i),
            "argon2id" => Ok(Algorithm::Argon2id),
            _ => Err(Error::AlgorithmInvalid),
        }
    }
}

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl From<Algorithm> for Ident<'static> {
    fn from(alg: Algorithm) -> Ident<'static> {
        alg.ident()
    }
}

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl<'a> TryFrom<Ident<'a>> for Algorithm {
    type Error = password_hash::Error;

    fn try_from(ident: Ident<'a>) -> Result<Algorithm, password_hash::Error> {
        match ident {
            ARGON2D_IDENT => Ok(Algorithm::Argon2d),
            ARGON2I_IDENT => Ok(Algorithm::Argon2i),
            ARGON2ID_IDENT => Ok(Algorithm::Argon2id),
            _ => Err(password_hash::Error::Algorithm),
        }
    }
}

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
#[derive(Clone)]
pub struct Argon2<'key> {
    /// Key array
    secret: Option<&'key [u8]>,

    /// Number of passes
    t_cost: u32,

    /// Amount of memory requested (kB)
    m_cost: u32,

    /// Number of lanes
    lanes: u32,

    /// Maximum number of threads
    threads: u32,

    /// Version number
    version: Version,
}

impl Default for Argon2<'_> {
    fn default() -> Self {
        Self::new(None, 3, 4096, 1, Version::default()).expect("invalid default Argon2 params")
    }
}

impl<'key> Argon2<'key> {
    /// Create a new Argon2 context
    pub fn new(
        secret: Option<&'key [u8]>,
        t_cost: u32,
        m_cost: u32,
        parallelism: u32,
        version: Version,
    ) -> Result<Self, Error> {
        let lanes = parallelism;

        if let Some(secret) = &secret {
            if MAX_SECRET < secret.len() {
                return Err(Error::SecretTooLong);
            }
        }

        // Validate memory cost
        if MIN_MEMORY > m_cost {
            return Err(Error::MemoryTooLittle);
        }

        if MAX_MEMORY < m_cost {
            return Err(Error::MemoryTooMuch);
        }

        if m_cost < 8 * lanes {
            return Err(Error::MemoryTooLittle);
        }

        // Validate time cost
        if t_cost < MIN_TIME {
            return Err(Error::TimeTooSmall);
        }

        // Validate lanes
        if MIN_LANES > lanes {
            return Err(Error::LanesTooFew);
        }

        if MAX_LANES < parallelism {
            return Err(Error::LanesTooMany);
        }

        // Validate threads
        if MIN_THREADS > lanes {
            return Err(Error::ThreadsTooFew);
        }

        if MAX_THREADS < parallelism {
            return Err(Error::ThreadsTooMany);
        }

        Ok(Self {
            secret,
            t_cost,
            m_cost,
            lanes,
            threads: parallelism,
            version,
        })
    }

    /// Hash a password and associated parameters into the provided output buffer.
    pub fn hash_password_into(
        &self,
        alg: Algorithm,
        pwd: &[u8],
        salt: &[u8],
        ad: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        // Validate output length
        if MIN_OUTLEN > out.len() {
            return Err(Error::OutputTooShort);
        }

        if MAX_OUTLEN < out.len() {
            return Err(Error::OutputTooLong);
        }

        if MAX_PWD_LENGTH < pwd.len() {
            return Err(Error::PwdTooLong);
        }

        // Validate salt (required param)
        if MIN_SALT_LENGTH > salt.len() {
            return Err(Error::SaltTooShort);
        }

        if MAX_SALT_LENGTH < salt.len() {
            return Err(Error::SaltTooLong);
        }

        // Validate associated data (optional param)
        if MAX_AD_LENGTH < ad.len() {
            return Err(Error::AdTooLong);
        }

        // Hashing all inputs
        let initial_hash = self.initial_hash(alg, pwd, salt, ad, out);

        let segment_length = Memory::segment_length_for_params(self.m_cost, self.lanes);
        let blocks_count = (segment_length * self.lanes * SYNC_POINTS) as usize;

        // TODO(tarcieri): support for stack-allocated memory blocks (i.e. no alloc)
        let mut blocks = vec![Block::default(); blocks_count];

        let memory = Memory::new(&mut blocks, segment_length);
        Instance::hash(self, alg, initial_hash, memory, out)
    }

    /// Hashes all the inputs into `blockhash[PREHASH_DIGEST_LENGTH]`.
    pub(crate) fn initial_hash(
        &self,
        alg: Algorithm,
        pwd: &[u8],
        salt: &[u8],
        ad: &[u8],
        out: &[u8],
    ) -> digest::Output<Blake2b> {
        let mut digest = Blake2b::new();
        digest.update(&self.lanes.to_le_bytes());
        digest.update(&(out.len() as u32).to_le_bytes());
        digest.update(&self.m_cost.to_le_bytes());
        digest.update(&self.t_cost.to_le_bytes());
        digest.update(&self.version.to_le_bytes());
        digest.update(&alg.to_le_bytes());
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

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl PasswordHasher for Argon2<'_> {
    type Params = Params;

    fn hash_password<'a>(
        &self,
        password: &[u8],
        alg_id: Option<Ident<'a>>,
        params: Params,
        salt: impl Into<Salt<'a>>,
    ) -> Result<PasswordHash<'a>, password_hash::Error> {
        let algorithm = alg_id
            .map(Algorithm::try_from)
            .transpose()?
            .unwrap_or_default();

        let salt = salt.into();
        let mut salt_arr = [0u8; 64];
        let salt_bytes = salt.b64_decode(&mut salt_arr)?;

        // TODO(tarcieri): support the `data` parameter (i.e. associated data)
        let ad = b"";

        let hasher = Self::new(
            self.secret,
            params.t_cost,
            params.m_cost,
            params.p_cost,
            params.version,
        )
        .map_err(|_| password_hash::Error::ParamValueInvalid)?;

        if MAX_PWD_LENGTH < password.len() {
            return Err(password_hash::Error::Password);
        }

        if !(MIN_SALT_LENGTH..=MAX_SALT_LENGTH).contains(&salt_bytes.len()) {
            // TODO(tarcieri): better error types for this case
            return Err(password_hash::Error::Crypto);
        }

        // Validate associated data (optional param)
        if MAX_AD_LENGTH < ad.len() {
            // TODO(tarcieri): better error types for this case
            return Err(password_hash::Error::Crypto);
        }

        // TODO(tarcieri): improve this API to eliminate redundant checks above
        let output = password_hash::Output::init_with(params.output_size, |out| {
            hasher
                .hash_password_into(algorithm, password, salt_bytes, ad, out)
                .map_err(|e| {
                    match e {
                        Error::OutputTooShort => password_hash::Error::OutputTooShort,
                        Error::OutputTooLong => password_hash::Error::OutputTooLong,
                        // Other cases are not returned from `hash_password_into`
                        // TODO(tarcieri): finer-grained error types?
                        _ => panic!("unhandled error type: {}", e),
                    }
                })
        })?;

        let res = Ok(PasswordHash {
            algorithm: algorithm.ident(),
            version: Some(params.version.into()),
            params: params.try_into()?,
            salt: Some(salt),
            hash: Some(output),
        });

        res
    }
}

#[cfg(all(test, feature = "password-hash"))]
mod tests {
    use super::{Argon2, Params, PasswordHasher, Salt};

    /// Example password only: don't use this as a real password!!!
    const EXAMPLE_PASSWORD: &[u8] = b"hunter42";

    #[test]
    fn decoded_salt_too_short() {
        let argon2 = Argon2::default();

        // Too short after decoding
        let salt = Salt::new("somesalt").unwrap();

        let res = argon2.hash_password(EXAMPLE_PASSWORD, None, Params::default(), salt);
        assert_eq!(res, Err(password_hash::Error::Crypto));
    }
}
