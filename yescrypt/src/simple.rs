//! Implementation of the `password-hash` crate API.

use crate::{Params, yescrypt_kdf};
use alloc::vec;
use mcf::{Base64, PasswordHash, PasswordHashRef};
use password_hash::{
    CustomizedPasswordHasher, Error, PasswordHasher, PasswordVerifier, Result, Version,
};

/// Identifier for yescrypt when encoding to the Modular Crypt Format, i.e. `$y$`
#[cfg(feature = "simple")]
const YESCRYPT_MCF_ID: &str = "y";

/// Base64 variant used by yescrypt.
const YESCRYPT_BASE64: Base64 = Base64::ShaCrypt;

/// yescrypt type for use with [`PasswordHasher`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Yescrypt;

impl CustomizedPasswordHasher<PasswordHash> for Yescrypt {
    type Params = Params;

    fn hash_password_customized(
        &self,
        password: &[u8],
        salt: &[u8],
        alg_id: Option<&str>,
        version: Option<Version>,
        params: Params,
    ) -> Result<PasswordHash> {
        // TODO(tarcieri): tunable hash output size?
        const HASH_SIZE: usize = 32;

        match alg_id {
            Some(YESCRYPT_MCF_ID) | None => (),
            _ => return Err(Error::Algorithm),
        }

        if version.is_some() {
            return Err(Error::Version);
        }

        let mut out = [0u8; HASH_SIZE];
        yescrypt_kdf(password, salt, &params, &mut out)?;

        // Begin building the Modular Crypt Format hash.
        let mut mcf_hash = PasswordHash::from_id(YESCRYPT_MCF_ID).expect("should be valid");

        // Add params string to the hash
        mcf_hash
            .push_displayable(params)
            .map_err(|_| Error::EncodingInvalid)?;

        // Add salt
        mcf_hash.push_base64(salt, YESCRYPT_BASE64);

        // Add yescrypt password hashing function output
        mcf_hash.push_base64(&out, YESCRYPT_BASE64);

        Ok(mcf_hash)
    }
}

impl PasswordHasher<PasswordHash> for Yescrypt {
    fn hash_password(&self, password: &[u8], salt: &[u8]) -> Result<PasswordHash> {
        self.hash_password_customized(password, salt, None, None, Params::default())
    }
}

impl PasswordVerifier<PasswordHash> for Yescrypt {
    fn verify_password(&self, password: &[u8], hash: &PasswordHash) -> Result<()> {
        self.verify_password(password, hash.as_password_hash_ref())
    }
}

impl PasswordVerifier<PasswordHashRef> for Yescrypt {
    fn verify_password(&self, password: &[u8], hash: &PasswordHashRef) -> Result<()> {
        // verify id matches `$y`
        if hash.id() != YESCRYPT_MCF_ID {
            return Err(Error::Algorithm);
        }

        let mut fields = hash.fields();

        // decode params
        let params: Params = fields
            .next()
            .ok_or(Error::EncodingInvalid)?
            .as_str()
            .parse()?;

        // decode salt
        let salt = fields
            .next()
            .ok_or(Error::EncodingInvalid)?
            .decode_base64(YESCRYPT_BASE64)
            .map_err(|_| Error::EncodingInvalid)?;

        // decode expected password hash
        let expected = fields
            .next()
            .ok_or(Error::EncodingInvalid)?
            .decode_base64(YESCRYPT_BASE64)
            .map_err(|_| Error::EncodingInvalid)?;

        // should be the last field
        if fields.next().is_some() {
            return Err(Error::EncodingInvalid);
        }

        let mut actual = vec![0u8; expected.len()];
        yescrypt_kdf(password, &salt, &params, &mut actual)?;

        if subtle::ConstantTimeEq::ct_ne(actual.as_slice(), &expected).into() {
            return Err(Error::PasswordInvalid);
        }

        Ok(())
    }
}
