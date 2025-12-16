//! Implementation of the `password-hash` crate API.

pub use password_hash::phc::{Ident, Output, PasswordHash, Salt};

use crate::{Params, Scrypt, scrypt};
use password_hash::{CustomizedPasswordHasher, Error, PasswordHasher, Result, Version};

/// Algorithm name
const ALG_NAME: &str = "scrypt";

/// Algorithm identifier
pub const ALG_ID: Ident = Ident::new_unwrap(ALG_NAME);

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

        let salt = Salt::new(salt)?;
        let len = params.len.unwrap_or(Params::RECOMMENDED_LEN);

        let mut buffer = [0u8; Output::MAX_LENGTH];
        let out = buffer.get_mut(..len).ok_or(Error::OutputSize)?;
        scrypt(password, &salt, &params, out).map_err(|_| Error::OutputSize)?;
        let output = Output::new(out)?;

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

#[cfg(test)]
mod tests {
    use super::{PasswordHash, Scrypt};
    use password_hash::PasswordVerifier;

    /// Test vector from passlib:
    /// <https://passlib.readthedocs.io/en/stable/lib/passlib.hash.scrypt.html>
    #[cfg(feature = "password-hash")]
    const EXAMPLE_PASSWORD_HASH: &str =
        "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";

    #[cfg(feature = "password-hash")]
    #[test]
    fn password_hash_verify_password() {
        let password = "password";
        let hash = PasswordHash::new(EXAMPLE_PASSWORD_HASH).unwrap();
        assert_eq!(Scrypt.verify_password(password.as_bytes(), &hash), Ok(()));
    }

    #[cfg(feature = "password-hash")]
    #[test]
    fn password_hash_reject_incorrect_password() {
        let hash = PasswordHash::new(EXAMPLE_PASSWORD_HASH).unwrap();
        assert!(Scrypt.verify_password(b"invalid", &hash).is_err());
    }
}
