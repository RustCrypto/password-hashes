//! Pure Rust implementation of the [Balloon] password hashing function as
//! specified in [this paper](https://eprint.iacr.org/2016/027.pdf).
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

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_root_url = "https://docs.rs/balloon-hash/0.1.0"
)]
#![warn(rust_2018_idioms, missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod error;
mod params;

pub use crate::{
    error::{Error, Result},
    params::Params,
};
use core::convert::{TryFrom, TryInto};
use core::marker::PhantomData;
use core::mem;
use core::ops::Rem;
use crypto_bigint::{ArrayDecoding, ArrayEncoding, NonZero};
use digest::generic_array::GenericArray;
use digest::Digest;
#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
pub use password_hash::{self, PasswordHash, PasswordHasher, PasswordVerifier};
#[cfg(all(feature = "alloc", feature = "password-hash"))]
use password_hash::{Decimal, Ident, ParamsString, Salt};

/// Balloon context.
///
/// This is the primary type of this crate's API, and contains the following:
///
/// - Default set of [`Params`] to be used
/// - (Optional) Secret key a.k.a. "pepper" to be used
#[derive(Clone, Default)]
pub struct Balloon<'key, D: Digest>
where
    GenericArray<u8, D::OutputSize>: ArrayDecoding,
    <GenericArray<u8, D::OutputSize> as ArrayDecoding>::Output:
        Rem<NonZero<<GenericArray<u8, D::OutputSize> as ArrayDecoding>::Output>>,
    <<GenericArray<u8, D::OutputSize> as ArrayDecoding>::Output as Rem<
        NonZero<<GenericArray<u8, D::OutputSize> as ArrayDecoding>::Output>,
    >>::Output: ArrayEncoding,
{
    /// Storing which hash function is used
    pub digest: PhantomData<D>,
    /// Algorithm parameters
    pub params: Params,
    /// Key array
    pub secret: Option<&'key [u8]>,
}

impl<'key, D: Digest> Balloon<'key, D>
where
    GenericArray<u8, D::OutputSize>: ArrayDecoding,
    <GenericArray<u8, D::OutputSize> as ArrayDecoding>::Output:
        Rem<NonZero<<GenericArray<u8, D::OutputSize> as ArrayDecoding>::Output>>,
    <<GenericArray<u8, D::OutputSize> as ArrayDecoding>::Output as Rem<
        NonZero<<GenericArray<u8, D::OutputSize> as ArrayDecoding>::Output>,
    >>::Output: ArrayEncoding,
{
    /// Create a new Balloon context.
    pub fn new(params: Params, secret: Option<&'key [u8]>) -> Self {
        Self {
            digest: PhantomData,
            params,
            secret,
        }
    }

    /// Hash a password and associated parameters.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn hash(&self, pwd: &[u8], salt: &[u8]) -> Result<GenericArray<u8, D::OutputSize>> {
        if self.params.p_cost.get() == 1 {
            let mut memory = alloc::vec![GenericArray::default(); usize::try_from(self.params.s_cost.get()).unwrap()];
            self.hash_internal(pwd, salt, &mut memory, None)
        } else {
            #[cfg(not(feature = "parallel"))]
            return Err(Error::ThreadsTooMany);
            #[cfg(feature = "parallel")]
            {
                use rayon::iter::{IntoParallelIterator, ParallelIterator};

                (1..=u64::from(self.params.p_cost.get()))
                    .into_par_iter()
                    .map_with((self.params, self.secret), |(params, secret), index| {
                        let mut memory = alloc::vec![
                            GenericArray::default(); usize::try_from(params.s_cost.get()).unwrap()
                        ];
                        // `PhantomData<D>` doesn't implement `Sync` unless `D` does, so we build a
                        // new `Balloon`, which is free
                        Self::new(*params, *secret).hash_internal(
                            pwd,
                            salt,
                            &mut memory,
                            Some(index),
                        )
                    })
                    .try_reduce(GenericArray::default, |a, b| {
                        Ok(a.into_iter().zip(b).map(|(a, b)| a ^ b).collect())
                    })
            }
        }
    }

    /// Hash a password and associated parameters.
    ///
    /// This method takes an explicit `memory_blocks` parameter which allows
    /// the caller to provide the backing storage for the algorithm's state:
    ///
    /// - Users with the `alloc` feature enabled can use [`Balloon::hash`]
    ///   to have it allocated for them.
    /// - `no_std` users on "heapless" targets can use an array of the [`GenericArray`] type
    ///   to stack allocate this buffer. It needs a minimum size of `s_cost`.
    pub fn hash_with_memory(
        &self,
        pwd: &[u8],
        salt: &[u8],
        memory_blocks: &mut [GenericArray<u8, D::OutputSize>],
    ) -> Result<GenericArray<u8, D::OutputSize>> {
        if self.params.p_cost.get() > 1 {
            return Err(Error::ThreadsTooMany);
        }

        self.hash_internal(pwd, salt, memory_blocks, None)
    }

    fn hash_internal(
        &self,
        pwd: &[u8],
        salt: &[u8],
        memory_blocks: &mut [GenericArray<u8, D::OutputSize>],
        thread_id: Option<u64>,
    ) -> Result<GenericArray<u8, D::OutputSize>> {
        // we will use `s_cost` to index arrays regularly
        let s_cost = usize::try_from(self.params.s_cost.get()).unwrap();

        let mut digest = D::new();

        // This is a direct translation of the `Balloon` from <https://eprint.iacr.org/2016/027.pdf> chapter 3.1.
        // int delta = 3 // Number of dependencies per block
        const DELTA: u64 = 3;
        // int cnt = 0 // A counter (used in security proof)
        let mut cnt: u64 = 0;
        // block_t buf[s_cost]): // The main buffer
        let buf = memory_blocks
            .get_mut(..s_cost)
            .ok_or(Error::MemoryTooLittle)?;

        // Step 1. Expand input into buffer.
        // buf[0] = hash(cnt++, passwd, salt)
        digest.update(cnt.to_le_bytes());
        cnt += 1;
        digest.update(pwd);
        digest.update(salt);

        if let Some(secret) = self.secret {
            digest.update(secret);
        }

        if let Some(thread_id) = thread_id {
            digest.update(thread_id.to_le_bytes());
        }

        buf[0] = digest.finalize_reset();

        // for m from 1 to s_cost-1:
        for m in 1..s_cost {
            // buf[m] = hash(cnt++, buf[m-1])
            digest.update(&cnt.to_le_bytes());
            cnt += 1;
            digest.update(&buf[m - 1]);
            buf[m] = digest.finalize_reset();
        }

        // Step 2. Mix buffer contents.
        // for t from 0 to t_cost-1:
        for t in 0..u64::from(self.params.t_cost.get()) {
            // for m from 0 to s_cost-1:
            for m in 0..s_cost {
                // Step 2a. Hash last and current blocks.
                // block_t prev = buf[(m-1) mod s_cost]
                let prev = if m == 0 {
                    buf.last().unwrap()
                } else {
                    &buf[m - 1]
                };

                // buf[m] = hash(cnt++, prev, buf[m])
                digest.update(&cnt.to_le_bytes());
                cnt += 1;
                digest.update(prev);
                digest.update(&buf[m]);
                buf[m] = digest.finalize_reset();

                // Step 2b. Hash in pseudorandomly chosen blocks.
                // for i from 0 to delta-1:
                for i in 0..DELTA {
                    // block_t idx_block = ints_to_block(t, m, i)
                    digest.update(&t.to_le_bytes());
                    digest.update(&u64::try_from(m).unwrap().to_le_bytes());
                    digest.update(&i.to_le_bytes());
                    let idx_block = digest.finalize_reset();

                    // int other = to_int(hash(cnt++, salt, idx_block)) mod s_cost
                    digest.update(&cnt.to_le_bytes());
                    cnt += 1;
                    digest.update(salt);

                    if let Some(secret) = self.secret {
                        digest.update(secret);
                    }

                    if let Some(thread_id) = thread_id {
                        digest.update(thread_id.to_le_bytes());
                    }

                    digest.update(idx_block);
                    let s_cost = {
                        let mut s_cost = GenericArray::<u8, D::OutputSize>::default();
                        s_cost[..mem::size_of::<u32>()]
                            .copy_from_slice(&self.params.s_cost.get().to_le_bytes());
                        NonZero::new(s_cost.into_bigint_le()).unwrap()
                    };
                    let other = digest.finalize_reset().into_bigint_le() % s_cost;
                    let other = usize::from_le_bytes(
                        other.to_le_byte_array()[..mem::size_of::<usize>()]
                            .try_into()
                            .unwrap(),
                    );

                    // buf[m] = hash(cnt++, buf[m], buf[other])
                    digest.update(&cnt.to_le_bytes());
                    cnt += 1;
                    digest.update(&buf[m]);
                    digest.update(&buf[other]);
                    buf[m] = digest.finalize_reset();
                }
            }
        }

        // Step 3. Extract output from buffer.
        // return buf[s_cost-1]
        Ok(buf.last().unwrap().clone())
    }
}

#[cfg(all(feature = "alloc", feature = "password-hash"))]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl<D: Digest> PasswordHasher for Balloon<'_, D>
where
    GenericArray<u8, D::OutputSize>: ArrayDecoding,
    <GenericArray<u8, D::OutputSize> as ArrayDecoding>::Output:
        Rem<NonZero<<GenericArray<u8, D::OutputSize> as ArrayDecoding>::Output>>,
    <<GenericArray<u8, D::OutputSize> as ArrayDecoding>::Output as Rem<
        NonZero<<GenericArray<u8, D::OutputSize> as ArrayDecoding>::Output>,
    >>::Output: ArrayEncoding,
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
            algorithm: Ident::new("balloon"),
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
        if let Some(alg_id) = alg_id {
            if alg_id.as_str() != "balloon" {
                return Err(password_hash::Error::Algorithm);
            }
        }

        if let Some(version) = version {
            if version != 1 {
                return Err(password_hash::Error::Version);
            }
        }

        let salt = salt.into();

        Self::new(params, self.secret).hash_password(password, salt.as_str())
    }
}

#[cfg(all(test, feature = "parallel", feature = "password-hash"))]
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
    let hasher = Balloon::<Sha256>::new(params, None);
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
