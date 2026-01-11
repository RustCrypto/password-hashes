//! Implementation of the `password-hash` crate API.

use crate::{Algorithm, Params, pbkdf2_hmac};
use password_hash::{
    CustomizedPasswordHasher, Error, PasswordHasher, Result,
    phc::{Output, PasswordHash, Salt},
};
use sha2::{Sha256, Sha512};

#[cfg(feature = "sha1")]
use sha1::Sha1;

/// PBKDF2 type for use with [`PasswordHasher`].
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Pbkdf2 {
    /// Algorithm to use
    algorithm: Algorithm,

    /// Default parameters to use.
    params: Params,
}

impl Pbkdf2 {
    /// Initialize [`Pbkdf2`] with default parameters.
    pub const fn new() -> Self {
        Self::new_with_params(Params::RECOMMENDED)
    }

    /// Initialize [`Pbkdf2`] with the provided parameters.
    pub const fn new_with_params(params: Params) -> Self {
        Self {
            algorithm: Algorithm::RECOMMENDED,
            params,
        }
    }
}

impl From<Params> for Pbkdf2 {
    fn from(params: Params) -> Self {
        Self::new_with_params(params)
    }
}

impl CustomizedPasswordHasher<PasswordHash> for Pbkdf2 {
    type Params = Params;

    fn hash_password_customized(
        &self,
        password: &[u8],
        salt: &[u8],
        alg_id: Option<&str>,
        version: Option<password_hash::Version>,
        params: Params,
    ) -> Result<PasswordHash> {
        let algorithm = alg_id
            .map(Algorithm::try_from)
            .transpose()?
            .unwrap_or(self.algorithm);

        // Versions unsupported
        if version.is_some() {
            return Err(Error::Version);
        }

        let salt = Salt::new(salt)?;

        let mut buffer = [0u8; Output::MAX_LENGTH];
        let out = buffer
            .get_mut(..params.output_length)
            .ok_or(Error::OutputSize)?;

        let f = match algorithm {
            #[cfg(feature = "sha1")]
            Algorithm::Pbkdf2Sha1 => pbkdf2_hmac::<Sha1>,
            Algorithm::Pbkdf2Sha256 => pbkdf2_hmac::<Sha256>,
            Algorithm::Pbkdf2Sha512 => pbkdf2_hmac::<Sha512>,
        };

        f(password, &salt, params.rounds, out);
        let output = Output::new(out)?;

        Ok(PasswordHash {
            algorithm: *algorithm.ident(),
            version: None,
            params: params.try_into()?,
            salt: Some(salt),
            hash: Some(output),
        })
    }
}

impl PasswordHasher<PasswordHash> for Pbkdf2 {
    fn hash_password_with_salt(&self, password: &[u8], salt: &[u8]) -> Result<PasswordHash> {
        self.hash_password_customized(password, salt, None, None, self.params)
    }
}
