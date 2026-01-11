//! Implementation of the `password-hash` traits for Modular Crypt Format (MCF) password hash
//! strings which begin with `$7$`:
//!
//! <https://man.archlinux.org/man/crypt.5#scrypt>

pub use mcf::{PasswordHash, PasswordHashRef};

use crate::{Algorithm, Params, Pbkdf2, pbkdf2_hmac};
use alloc::string::String;
use mcf::Base64;
use password_hash::{CustomizedPasswordHasher, Error, PasswordHasher, Result, Version};
use sha2::{Sha256, Sha512};

#[cfg(feature = "sha1")]
use sha1::Sha1;

#[cfg(test)]
use alloc::vec::Vec;

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
            .get_mut(..params.output_len())
            .ok_or(Error::OutputSize)?;

        let f = match algorithm {
            #[cfg(feature = "sha1")]
            Algorithm::Pbkdf2Sha1 => pbkdf2_hmac::<Sha1>,
            Algorithm::Pbkdf2Sha256 => pbkdf2_hmac::<Sha256>,
            Algorithm::Pbkdf2Sha512 => pbkdf2_hmac::<Sha512>,
        };

        f(password, salt, params.rounds(), out);

        let mut mcf_hash = PasswordHash::from_id(algorithm.to_str()).expect("should have valid ID");

        mcf_hash
            .push_displayable(params)
            .map_err(|_| Error::EncodingInvalid)?;

        mcf_hash
            .push_str(&base64_encode(salt))
            .map_err(|_| Error::EncodingInvalid)?;

        mcf_hash
            .push_str(&base64_encode(out))
            .map_err(|_| Error::EncodingInvalid)?;

        Ok(mcf_hash)
    }
}

impl PasswordHasher<PasswordHash> for Pbkdf2 {
    fn hash_password_with_salt(&self, password: &[u8], salt: &[u8]) -> Result<PasswordHash> {
        self.hash_password_customized(password, salt, None, None, self.params)
    }
}

// Base64 support: PBKDF2 uses a variant of standard unpadded Base64 which substitutes the `+`
// character for `.` and this is a distinct encoding from the bcrypt and crypt Base64 variants.

#[cfg(test)]
fn base64_decode(base64: &str) -> Result<Vec<u8>> {
    Base64::B64
        .decode_vec(&base64.replace('.', "+"))
        .map_err(|_| Error::EncodingInvalid)
}

fn base64_encode(bytes: &[u8]) -> String {
    Base64::B64.encode_string(bytes).replace('+', ".")
}

// TODO(tarcieri): tests for SHA-1 and SHA-512
#[cfg(test)]
mod tests {
    use super::base64_decode;
    use crate::{Params, Pbkdf2};
    use mcf::PasswordHash;
    use password_hash::CustomizedPasswordHasher;

    // Example adapted from:
    // <https://passlib.readthedocs.io/en/stable/lib/passlib.hash.pbkdf2_digest.html>
    #[test]
    fn hash_password_sha256() {
        const EXAMPLE_PASSWORD: &[u8] = b"password";
        const EXAMPLE_ROUNDS: u32 = 8000;
        const EXAMPLE_SALT: &str = "XAuBMIYQQogxRg";
        const EXAMPLE_HASH: &str =
            "$pbkdf2-sha256$8000$XAuBMIYQQogxRg$tRRlz8hYn63B9LYiCd6PRo6FMiunY9ozmMMI3srxeRE";

        let salt = base64_decode(EXAMPLE_SALT).unwrap();
        let params = Params::new(EXAMPLE_ROUNDS);

        let actual_hash: PasswordHash = Pbkdf2::default()
            .hash_password_with_params(EXAMPLE_PASSWORD, salt.as_slice(), params)
            .unwrap();

        let expected_hash = PasswordHash::new(EXAMPLE_HASH).unwrap();
        assert_eq!(expected_hash, actual_hash);
    }

    // Example adapted from:
    // <https://github.com/hlandau/passlib/blob/8f820e0/hash/pbkdf2/pbkdf2_test.go>
    #[test]
    fn hash_password_sha512() {
        const EXAMPLE_PASSWORD: &[u8] = b"abcdefghijklmnop";
        const EXAMPLE_ROUNDS: u32 = 25000;
        const EXAMPLE_SALT: &str = "O4fwPmdMyRmDUIrx/h9jTA";
        const EXAMPLE_HASH: &str = "$pbkdf2-sha512$25000$O4fwPmdMyRmDUIrx/h9jTA$Xlp267ZwEbG4aOpN3Bve/ATo3rFA7WH8iMdS16Xbe9rc6P5welk1yiXEMPy7.BFp0qsncipHumaW1trCWVvq/A";

        let salt = base64_decode(EXAMPLE_SALT).unwrap();
        let params = Params::new_with_output_len(EXAMPLE_ROUNDS, 64);

        let actual_hash: PasswordHash = Pbkdf2::SHA512
            .hash_password_with_params(EXAMPLE_PASSWORD, salt.as_slice(), params)
            .unwrap();

        let expected_hash = PasswordHash::new(EXAMPLE_HASH).unwrap();
        assert_eq!(expected_hash, actual_hash);
    }
}
