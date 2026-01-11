//! Implementation of the `password-hash` traits for Modular Crypt Format (MCF) password hash
//! strings which begin with `$7$`:
//!
//! <https://man.archlinux.org/man/crypt.5#scrypt>

pub use mcf::{PasswordHash, PasswordHashRef};

use crate::{Algorithm, Params, Pbkdf2, pbkdf2_hmac};
use mcf::Base64;
use password_hash::{CustomizedPasswordHasher, Error, PasswordHasher, Result, Version};
use sha2::{Sha256, Sha512};

#[cfg(feature = "sha1")]
use sha1::Sha1;

/// Base64 variant used by PBKDF2's MCF implementation: unpadded standard Base64.
const PBKDF2_BASE64: Base64 = Base64::B64;

impl CustomizedPasswordHasher<PasswordHash> for Pbkdf2 {
    type Params = Params;

    fn hash_password_customized(
        &self,
        password: &[u8],
        salt: &[u8],
        alg_id: Option<&str>,
        version: Option<Version>,
        params: Params,
    ) -> Result<PasswordHash> {
        let algorithm = alg_id
            .map(Algorithm::try_from)
            .transpose()?
            .unwrap_or(self.algorithm);

        if version.is_some() {
            return Err(Error::Version);
        }

        let mut buffer = [0u8; Params::MAX_LENGTH];
        let out = buffer
            .get_mut(..params.output_length)
            .ok_or(Error::OutputSize)?;

        let f = match algorithm {
            #[cfg(feature = "sha1")]
            Algorithm::Pbkdf2Sha1 => pbkdf2_hmac::<Sha1>,
            Algorithm::Pbkdf2Sha256 => pbkdf2_hmac::<Sha256>,
            Algorithm::Pbkdf2Sha512 => pbkdf2_hmac::<Sha512>,
        };

        f(password, salt, params.rounds, out);

        let mut mcf_hash = PasswordHash::from_id(algorithm.to_str()).expect("should have valid ID");

        mcf_hash
            .push_displayable(params)
            .map_err(|_| Error::EncodingInvalid)?;
        mcf_hash.push_base64(salt, PBKDF2_BASE64);
        mcf_hash.push_base64(out, PBKDF2_BASE64);

        Ok(mcf_hash)
    }
}

impl PasswordHasher<PasswordHash> for Pbkdf2 {
    fn hash_password_with_salt(&self, password: &[u8], salt: &[u8]) -> Result<PasswordHash> {
        self.hash_password_customized(password, salt, None, None, self.params)
    }
}

// TODO(tarcieri): tests for SHA-1 and SHA-512
#[cfg(test)]
mod tests {
    use super::PBKDF2_BASE64;
    use crate::{Params, Pbkdf2};
    use mcf::PasswordHash;
    use password_hash::CustomizedPasswordHasher;

    // Example adapted from:
    // <https://passlib.readthedocs.io/en/stable/lib/passlib.hash.pbkdf2_digest.html>

    const EXAMPLE_PASSWORD: &[u8] = b"password";
    const EXAMPLE_ROUNDS: u32 = 8000;
    const EXAMPLE_SALT: &str = "XAuBMIYQQogxRg";
    const EXAMPLE_HASH: &str =
        "$pbkdf2-sha256$8000$XAuBMIYQQogxRg$tRRlz8hYn63B9LYiCd6PRo6FMiunY9ozmMMI3srxeRE";

    #[test]
    fn hash_password_sha256() {
        let salt = PBKDF2_BASE64.decode_vec(EXAMPLE_SALT).unwrap();
        let params = Params::new(EXAMPLE_ROUNDS);

        let actual_hash: PasswordHash = Pbkdf2::default()
            .hash_password_with_params(EXAMPLE_PASSWORD, salt.as_slice(), params)
            .unwrap();

        let expected_hash = PasswordHash::new(EXAMPLE_HASH).unwrap();
        assert_eq!(expected_hash, actual_hash);
    }
}
