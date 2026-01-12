//! Implementation of the `password-hash` crate API.

pub use mcf::{PasswordHash, PasswordHashRef};

use crate::{BLOCK_SIZE_SHA256, BLOCK_SIZE_SHA512, Params, algorithm::Algorithm};
use base64ct::{Base64ShaCrypt, Encoding};
use core::str::FromStr;
use mcf::Base64;
use password_hash::{
    CustomizedPasswordHasher, Error, PasswordHasher, PasswordVerifier, Result, Version,
};
use subtle::ConstantTimeEq;

/// SHA-crypt type for use with the [`PasswordHasher`] and [`PasswordVerifier`] traits, which can
/// produce and verify password hashes in [`Modular Crypt Format`][`mcf`].
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct ShaCrypt {
    /// Default algorithm to use when generating password hashes.
    algorithm: Algorithm,

    /// Default params to use when generating password hashes.
    params: Params,
}

impl ShaCrypt {
    /// SHA-crypt configured with SHA-256 as the default.
    pub const SHA256: Self = Self::new(Algorithm::Sha256Crypt, Params::RECOMMENDED);

    /// SHA-crypt configured with SHA-512 as the default.
    pub const SHA512: Self = Self::new(Algorithm::Sha512Crypt, Params::RECOMMENDED);

    /// Create a new password hasher with customized algorithm and params.
    pub const fn new(algorithm: Algorithm, params: Params) -> Self {
        Self { algorithm, params }
    }
}

impl CustomizedPasswordHasher<PasswordHash> for ShaCrypt {
    type Params = Params;

    fn hash_password_customized(
        &self,
        password: &[u8],
        salt: &[u8],
        alg_id: Option<&str>,
        version: Option<Version>,
        params: Params,
    ) -> Result<PasswordHash> {
        let alg = alg_id
            .map(Algorithm::try_from)
            .transpose()?
            .unwrap_or(self.algorithm);

        if version.is_some() {
            return Err(Error::Version);
        }

        // We compute the function over the Base64-encoded salt
        let salt = Base64ShaCrypt::encode_string(salt);
        let mut mcf_hash = PasswordHash::from_id(alg.to_str()).expect("should have valid ID");

        mcf_hash
            .push_displayable(params)
            .expect("should be valid field");

        mcf_hash
            .push_str(&salt)
            .map_err(|_| Error::EncodingInvalid)?;

        match alg {
            Algorithm::Sha256Crypt => {
                let out = sha256_crypt_core(password, salt.as_bytes(), params);
                mcf_hash.push_base64(&out, Base64::Crypt);
            }
            Algorithm::Sha512Crypt => {
                let out = sha512_crypt_core(password, salt.as_bytes(), params);
                mcf_hash.push_base64(&out, Base64::Crypt);
            }
        }

        Ok(mcf_hash)
    }
}

impl PasswordHasher<PasswordHash> for ShaCrypt {
    fn hash_password_with_salt(&self, password: &[u8], salt: &[u8]) -> Result<PasswordHash> {
        self.hash_password_customized(password, salt, None, None, self.params)
    }
}

impl PasswordVerifier<PasswordHash> for ShaCrypt {
    fn verify_password(&self, password: &[u8], hash: &PasswordHash) -> Result<()> {
        self.verify_password(password, hash.as_password_hash_ref())
    }
}

impl PasswordVerifier<PasswordHashRef> for ShaCrypt {
    fn verify_password(&self, password: &[u8], hash: &PasswordHashRef) -> Result<()> {
        let alg = hash.id().parse::<Algorithm>()?;
        let mut fields = hash.fields();
        let mut next = fields.next().ok_or(Error::EncodingInvalid)?;

        let mut params = Params::default();

        // decode params
        // TODO(tarcieri): `mcf::Field` helper methods for parsing params?
        if let Ok(p) = Params::from_str(next.as_str()) {
            params = p;
            next = fields.next().ok_or(Error::EncodingInvalid)?;
        }

        let salt = next.as_str().as_bytes();

        // decode expected password hash
        let expected = fields
            .next()
            .ok_or(Error::EncodingInvalid)?
            .decode_base64(Base64::Crypt)
            .map_err(|_| Error::EncodingInvalid)?;

        // should be the last field
        if fields.next().is_some() {
            return Err(Error::EncodingInvalid);
        }

        let is_valid = match alg {
            Algorithm::Sha256Crypt => sha256_crypt_core(password, salt, params)
                .as_ref()
                .ct_eq(&expected),
            Algorithm::Sha512Crypt => sha512_crypt_core(password, salt, params)
                .as_ref()
                .ct_eq(&expected),
        };

        if (!is_valid).into() {
            return Err(Error::PasswordInvalid);
        }

        Ok(())
    }
}

impl PasswordVerifier<str> for ShaCrypt {
    fn verify_password(&self, password: &[u8], hash: &str) -> password_hash::Result<()> {
        // TODO(tarcieri): better mapping from `mcf::Error` and `password_hash::Error`?
        let hash = PasswordHashRef::new(hash).map_err(|_| Error::EncodingInvalid)?;
        self.verify_password(password, hash)
    }
}

impl From<Algorithm> for ShaCrypt {
    fn from(algorithm: Algorithm) -> Self {
        Self {
            algorithm,
            params: Params::default(),
        }
    }
}

impl From<Params> for ShaCrypt {
    fn from(params: Params) -> Self {
        Self {
            algorithm: Algorithm::default(),
            params,
        }
    }
}

/// SHA-256-crypt core function: uses an algorithm-specific transposition table.
fn sha256_crypt_core(password: &[u8], salt: &[u8], params: Params) -> [u8; BLOCK_SIZE_SHA256] {
    let output = super::sha256_crypt(password, salt, params);
    let transposition_table = [
        20, 10, 0, 11, 1, 21, 2, 22, 12, 23, 13, 3, 14, 4, 24, 5, 25, 15, 26, 16, 6, 17, 7, 27, 8,
        28, 18, 29, 19, 9, 30, 31,
    ];

    let mut transposed = [0u8; BLOCK_SIZE_SHA256];
    for (i, &ti) in transposition_table.iter().enumerate() {
        transposed[i] = output[ti as usize];
    }

    transposed
}

/// SHA-512-crypt core function: uses an algorithm-specific transposition table.
fn sha512_crypt_core(password: &[u8], salt: &[u8], params: Params) -> [u8; BLOCK_SIZE_SHA512] {
    let output = super::sha512_crypt(password, salt, params);
    let transposition_table = [
        42, 21, 0, 1, 43, 22, 23, 2, 44, 45, 24, 3, 4, 46, 25, 26, 5, 47, 48, 27, 6, 7, 49, 28, 29,
        8, 50, 51, 30, 9, 10, 52, 31, 32, 11, 53, 54, 33, 12, 13, 55, 34, 35, 14, 56, 57, 36, 15,
        16, 58, 37, 38, 17, 59, 60, 39, 18, 19, 61, 40, 41, 20, 62, 63,
    ];

    let mut transposed = [0u8; BLOCK_SIZE_SHA512];
    for (i, &ti) in transposition_table.iter().enumerate() {
        transposed[i] = output[ti as usize];
    }

    transposed
}
