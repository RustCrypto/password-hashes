//! Implementation of the `password-hash` crate API.

use crate::{Params, scrypt};
use password_hash::{
    CustomizedPasswordHasher, Error, PasswordHasher, Result, Version,
    phc::{Ident, Output, PasswordHash, Salt},
};

/// Algorithm name
const ALG_NAME: &str = "scrypt";

/// Algorithm identifier
pub const ALG_ID: Ident = Ident::new_unwrap(ALG_NAME);

/// scrypt type for use with [`PasswordHasher`].
///
/// See the [crate docs](crate) for a usage example.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Scrypt;

impl CustomizedPasswordHasher<PasswordHash> for Scrypt {
    type Params = Params;

    fn hash_password_customized(
        &self,
        password: &[u8],
        salt: &[u8],
        alg_id: Option<&str>,
        version: Option<Version>,
        params: Params,
    ) -> Result<PasswordHash> {
        match alg_id {
            Some(ALG_NAME) | None => (),
            Some(_) => return Err(Error::Algorithm),
        }

        // Versions unsupported
        if version.is_some() {
            return Err(Error::Version);
        }

        let salt = Salt::new(salt).map_err(|_| Error::SaltInvalid)?;
        let len = params.len.unwrap_or(Params::RECOMMENDED_LEN);

        let mut buffer = [0u8; Output::MAX_LENGTH];
        let out = buffer.get_mut(..len).ok_or(Error::OutputSize)?;
        scrypt(password, &salt, &params, out).map_err(|_| Error::OutputSize)?;
        let output = Output::new(out).map_err(|_| Error::OutputSize)?;

        Ok(PasswordHash {
            algorithm: ALG_ID,
            version: None,
            params: params.try_into()?,
            salt: Some(salt),
            hash: Some(output),
        })
    }
}

impl PasswordHasher<PasswordHash> for Scrypt {
    fn hash_password_with_salt(&self, password: &[u8], salt: &[u8]) -> Result<PasswordHash> {
        self.hash_password_customized(password, salt, None, None, Params::default())
    }
}
