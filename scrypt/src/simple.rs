//! Implementation of the `password-hash` crate API.

use crate::{Params, scrypt};
use core::cmp::Ordering;
use password_hash::{
    CustomizedPasswordHasher, Error, PasswordHash, PasswordHasher, Result, Version,
    phc::{Ident, Output, Salt},
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

impl CustomizedPasswordHasher for Scrypt {
    type Params = Params;

    fn hash_password_customized<'a>(
        &self,
        password: &[u8],
        alg_id: Option<&str>,
        version: Option<Version>,
        params: Params,
        salt: &'a str,
    ) -> Result<PasswordHash<'a>> {
        match alg_id {
            Some(ALG_NAME) | None => (),
            Some(_) => return Err(Error::Algorithm),
        }

        // Versions unsupported
        if version.is_some() {
            return Err(Error::Version);
        }

        let salt = Salt::from_b64(salt)?;
        let mut salt_arr = [0u8; 64];
        let salt_bytes = salt.decode_b64(&mut salt_arr)?;
        let len = params.len.unwrap_or(Params::RECOMMENDED_LEN);

        let output = Output::init_with(len, |out| {
            scrypt(password, salt_bytes, &params, out).map_err(|_| {
                let provided = if out.is_empty() {
                    Ordering::Less
                } else {
                    Ordering::Greater
                };

                password_hash::Error::OutputSize {
                    provided,
                    expected: 0, // TODO(tarcieri): calculate for `Ordering::Greater` case
                }
            })
        })?;

        Ok(PasswordHash {
            algorithm: ALG_ID,
            version: None,
            params: params.try_into()?,
            salt: Some(salt),
            hash: Some(output),
        })
    }
}

impl PasswordHasher for Scrypt {
    fn hash_password<'a>(&self, password: &[u8], salt: &'a str) -> Result<PasswordHash<'a>> {
        self.hash_password_customized(password, None, None, Params::default(), salt)
    }
}
