//! Implementation of the `password-hash` crate API.

use crate::{scrypt, Params};
use password_hash::{Decimal, Error, Ident, Output, PasswordHash, PasswordHasher, Result, Salt};

/// Algorithm identifier
pub const ALG_ID: Ident = Ident::new_unwrap("scrypt");

/// scrypt type for use with [`PasswordHasher`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(docsrs, doc(cfg(feature = "simple")))]
pub struct Scrypt;

impl PasswordHasher for Scrypt {
    type Params = Params;

    fn hash_password_customized<'a>(
        &self,
        password: &[u8],
        alg_id: Option<Ident<'a>>,
        version: Option<Decimal>,
        params: Params,
        salt: impl Into<Salt<'a>>,
    ) -> Result<PasswordHash<'a>> {
        if !matches!(alg_id, Some(ALG_ID) | None) {
            return Err(Error::Algorithm);
        }

        // Versions unsupported
        if version.is_some() {
            return Err(Error::Version);
        }

        let salt = salt.into();
        let mut salt_arr = [0u8; 64];
        let salt_bytes = salt.b64_decode(&mut salt_arr)?;

        let output = Output::init_with(params.len, |out| {
            scrypt(password, salt_bytes, &params, out).map_err(|_e| {
                // TODO(tarcieri): handle output variants
                Error::OutputTooLong
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
