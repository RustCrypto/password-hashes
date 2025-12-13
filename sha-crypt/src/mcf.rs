//! Implementation of the `password-hash` crate API.

pub use mcf::{PasswordHash, PasswordHashRef};

use crate::{BLOCK_SIZE_SHA256, BLOCK_SIZE_SHA512, Params, sha256_crypt, sha512_crypt};
use base64ct::{Base64ShaCrypt, Encoding};
use core::{marker::PhantomData, str::FromStr};
use mcf::Base64;
use password_hash::{
    CustomizedPasswordHasher, Error, PasswordHasher, PasswordVerifier, Result, Version,
};
use sha2::{Sha256, Sha512};

/// SHA-crypt uses digest-specific parameters.
pub trait ShaCryptCore {
    /// Modular Crypt Format ID.
    const MCF_ID: &'static str;

    /// Output data
    type Output: AsRef<[u8]>;

    /// Core function
    fn sha_crypt_core(password: &[u8], salt: &[u8], params: &Params) -> Self::Output;
}

/// sha-crypt type for use with [`PasswordHasher`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ShaCrypt<D> {
    phantom: PhantomData<D>,
}

/// SHA-crypt initialized using SHA-256
pub const SHA256_CRYPT: ShaCrypt<Sha256> = ShaCrypt {
    phantom: PhantomData,
};

/// SHA-crypt initialized using SHA-512
pub const SHA512_CRYPT: ShaCrypt<Sha512> = ShaCrypt {
    phantom: PhantomData,
};

impl<D> CustomizedPasswordHasher<PasswordHash> for ShaCrypt<D>
where
    Self: ShaCryptCore,
{
    type Params = Params;

    fn hash_password_customized(
        &self,
        password: &[u8],
        salt: &[u8],
        alg_id: Option<&str>,
        version: Option<Version>,
        params: Params,
    ) -> Result<PasswordHash> {
        if alg_id.is_some() && alg_id != Some(Self::MCF_ID) {
            return Err(Error::Algorithm);
        }

        if version.is_some() {
            return Err(Error::Version);
        }

        // We compute the function over the Base64-encoded salt
        let salt = Base64ShaCrypt::encode_string(salt);
        let out = Self::sha_crypt_core(password, salt.as_bytes(), &params);

        let mut mcf_hash = PasswordHash::from_id(Self::MCF_ID).expect("should have valid ID");

        mcf_hash
            .push_displayable(&params)
            .expect("should be valid field");

        mcf_hash
            .push_str(&salt)
            .map_err(|_| Error::EncodingInvalid)?;

        mcf_hash.push_base64(out.as_ref(), Base64::ShaCrypt);

        Ok(mcf_hash)
    }
}

impl<D> PasswordHasher<PasswordHash> for ShaCrypt<D>
where
    Self: ShaCryptCore,
{
    fn hash_password_with_salt(&self, password: &[u8], salt: &[u8]) -> Result<PasswordHash> {
        self.hash_password_customized(password, salt, None, None, Params::default())
    }
}

impl<D> PasswordVerifier<PasswordHash> for ShaCrypt<D>
where
    Self: ShaCryptCore,
{
    fn verify_password(&self, password: &[u8], hash: &PasswordHash) -> Result<()> {
        self.verify_password(password, hash.as_password_hash_ref())
    }
}

impl<D> PasswordVerifier<PasswordHashRef> for ShaCrypt<D>
where
    Self: ShaCryptCore,
{
    fn verify_password(&self, password: &[u8], hash: &PasswordHashRef) -> Result<()> {
        if hash.id() != Self::MCF_ID {
            return Err(Error::Algorithm);
        }

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
            .decode_base64(Base64::ShaCrypt)
            .map_err(|_| Error::EncodingInvalid)?;

        // should be the last field
        if fields.next().is_some() {
            return Err(Error::EncodingInvalid);
        }

        let actual = Self::sha_crypt_core(password, salt, &params);

        if subtle::ConstantTimeEq::ct_ne(actual.as_ref(), &expected).into() {
            return Err(Error::PasswordInvalid);
        }

        Ok(())
    }
}

impl ShaCryptCore for ShaCrypt<Sha256> {
    const MCF_ID: &'static str = "5";
    type Output = [u8; BLOCK_SIZE_SHA256];

    /// Core function
    fn sha_crypt_core(password: &[u8], salt: &[u8], params: &Params) -> Self::Output {
        let output = sha256_crypt(password, salt, params);
        let transposition_table = [
            20, 10, 0, 11, 1, 21, 2, 22, 12, 23, 13, 3, 14, 4, 24, 5, 25, 15, 26, 16, 6, 17, 7, 27,
            8, 28, 18, 29, 19, 9, 30, 31,
        ];

        let mut transposed = [0u8; BLOCK_SIZE_SHA256];
        for (i, &ti) in transposition_table.iter().enumerate() {
            transposed[i] = output[ti as usize];
        }

        transposed
    }
}

impl ShaCryptCore for ShaCrypt<Sha512> {
    const MCF_ID: &'static str = "6";
    type Output = [u8; BLOCK_SIZE_SHA512];

    /// Core function
    fn sha_crypt_core(password: &[u8], salt: &[u8], params: &Params) -> Self::Output {
        let output = sha512_crypt(password, salt, params);
        let transposition_table = [
            42, 21, 0, 1, 43, 22, 23, 2, 44, 45, 24, 3, 4, 46, 25, 26, 5, 47, 48, 27, 6, 7, 49, 28,
            29, 8, 50, 51, 30, 9, 10, 52, 31, 32, 11, 53, 54, 33, 12, 13, 55, 34, 35, 14, 56, 57,
            36, 15, 16, 58, 37, 38, 17, 59, 60, 39, 18, 19, 61, 40, 41, 20, 62, 63,
        ];

        let mut transposed = [0u8; BLOCK_SIZE_SHA512];
        for (i, &ti) in transposition_table.iter().enumerate() {
            transposed[i] = output[ti as usize];
        }

        transposed
    }
}
