//! Argon2 password hashing function.

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_docs)]
#![allow(clippy::too_many_arguments, clippy::absurd_extreme_comparisons)]

#[macro_use]
extern crate alloc;

mod block;
mod error;
mod instance;

pub use crate::error::{Error, Result};

use crate::{block::Block, instance::Instance};
use blake2::{digest, Blake2b, Digest};

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

/// Minimum number of memory blocks (each of [`BLOCK_SIZE`] bytes)
pub const MIN_MEMORY: u32 = 2 * SYNC_POINTS; // 2 blocks per slice

/// Maximum number of memory blocks (each of [`BLOCK_SIZE`] bytes)
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

/// Memory block size in bytes
pub const BLOCK_SIZE: usize = 1024;

/// Number of synchronization points between lanes per pass
const SYNC_POINTS: u32 = 4;

/// Argon2 primitive type: variants of the algorithm
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Algorithm {
    /// Argon2d: optimizes memory-hardness but vulnerable to side-channels
    Argon2d = 0,

    /// Argon2i: hardened against side-channels but less memory-hard than Argon2d
    Argon2i = 1,

    /// Argon2id (default): mixes Argon2i and Argon2d passes, thereby providing
    /// the combined benefits of Argon2i and Argon2d.
    Argon2id = 2,
}

impl Default for Algorithm {
    fn default() -> Algorithm {
        Algorithm::Argon2id
    }
}

impl Algorithm {
    /// Serialize primitive type as little endian bytes
    fn to_le_bytes(self) -> [u8; 4] {
        (self as u32).to_le_bytes()
    }
}

/// Version of the algorithm
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Version {
    /// Version 16 (0x10 in hex)
    ///
    /// Performs overwrite internally
    V0x10 = 0x10,

    /// Version 19 (0x13 in hex, default)
    ///
    /// Performs XOR internally
    V0x13 = 0x13,
}

impl Version {
    /// Serialize version as little endian bytes
    fn to_le_bytes(self) -> [u8; 4] {
        (self as u32).to_le_bytes()
    }
}

impl Default for Version {
    fn default() -> Self {
        Self::V0x13
    }
}

/// Argon2 context
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

    /// Segment length
    pub(crate) segment_length: u32,

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
    ) -> Result<Self> {
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
        if MIN_TIME > t_cost {
            return Err(Error::TimeTooSmall);
        }

        if MAX_TIME < t_cost {
            return Err(Error::TimeTooLarge);
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

        // Align memory size
        // Minimum memory_blocks = 8L blocks, where L is the number of lanes
        let memory_blocks = if m_cost < 2 * SYNC_POINTS * lanes {
            2 * SYNC_POINTS * lanes
        } else {
            m_cost
        };

        let segment_length = memory_blocks / (lanes * SYNC_POINTS);

        Ok(Self {
            secret,
            t_cost,
            m_cost,
            lanes,
            threads: parallelism,
            segment_length,
            version,
        })
    }

    /// Function that performs memory-hard hashing with certain degree of parallelism.
    pub fn hash_password(
        &self,
        alg: Algorithm,
        pwd: &[u8],
        salt: &[u8],
        ad: &[u8],
        out: &mut [u8],
    ) -> Result<()> {
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

        let memory_blocks = (self.segment_length * self.lanes * SYNC_POINTS) as usize;

        // Hashing all inputs
        #[allow(unused_mut)]
        let mut initial_hash = self.initial_hash(alg, pwd, salt, ad, out);

        // TODO(tarcieri): support for stack-allocated memory blocks (i.e. no alloc)
        let mut memory = vec![Block::default(); memory_blocks];

        Instance::hash(self, alg, initial_hash, &mut memory, out)
    }

    /// Hashes all the inputs into `blockhash[PREHASH_DIGEST_LENGTH]`.
    fn initial_hash(
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
