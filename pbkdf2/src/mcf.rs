//! Implementation of the `password-hash` traits for Modular Crypt Format (MCF) password hash
//! strings which begin with `$pbkdf$`, `$pbkdf-sha256$`, or `$pbkdf-sha512`:
//!
//! <https://passlib.readthedocs.io/en/stable/lib/passlib.hash.pbkdf2_digest.html>
//!
//! PBKDF2's MCF strings can be distinguished from PHC strings by whether the parameters
//! field contains `rounds=` or not: if the number of rounds does NOT contain `rounds=`, but just a
//! bare number of rounds, then it's MCF format. If it DOES contain `rounds=`, then it's PHC.

pub use mcf::{PasswordHash, PasswordHashRef};

use crate::{Algorithm, Params, Pbkdf2, pbkdf2_hmac};
use alloc::{string::String, vec::Vec};
use mcf::Base64;
use password_hash::{
    CustomizedPasswordHasher, Error, PasswordHasher, PasswordVerifier, Result, Version,
};
use sha2::{Sha256, Sha512};

#[cfg(feature = "sha1")]
use sha1::Sha1;

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

impl PasswordVerifier<PasswordHash> for Pbkdf2 {
    fn verify_password(&self, password: &[u8], hash: &PasswordHash) -> Result<()> {
        self.verify_password(password, hash.as_password_hash_ref())
    }
}

impl PasswordVerifier<PasswordHashRef> for Pbkdf2 {
    fn verify_password(&self, password: &[u8], hash: &PasswordHashRef) -> Result<()> {
        let algorithm = hash.id().parse::<Algorithm>()?;
        let mut fields = hash.fields();
        let mut next = fields.next().ok_or(Error::EncodingInvalid)?;
        let mut params = Params::default();

        // decode params
        if let Ok(p) = next.as_str().parse::<Params>() {
            params = p;
            next = fields.next().ok_or(Error::EncodingInvalid)?;
        }

        let salt = base64_decode(next.as_str())?;

        // decode expected password hash
        let expected = fields
            .next()
            .ok_or(Error::EncodingInvalid)
            .and_then(|field| base64_decode(field.as_str()))?;

        // should be the last field
        if fields.next().is_some() {
            return Err(Error::EncodingInvalid);
        }

        let mut buffer = [0u8; Params::MAX_LENGTH];
        let out = buffer.get_mut(..expected.len()).ok_or(Error::OutputSize)?;

        let f = match algorithm {
            #[cfg(feature = "sha1")]
            Algorithm::Pbkdf2Sha1 => pbkdf2_hmac::<Sha1>,
            Algorithm::Pbkdf2Sha256 => pbkdf2_hmac::<Sha256>,
            Algorithm::Pbkdf2Sha512 => pbkdf2_hmac::<Sha512>,
        };

        f(password, &salt, params.rounds(), out);

        // TODO(tarcieri): use `subtle` or `ctutils` for comparison
        if out
            .iter()
            .zip(expected.iter())
            .fold(0, |acc, (a, b)| acc | (a ^ b))
            == 0
        {
            Ok(())
        } else {
            Err(Error::PasswordInvalid)
        }
    }
}

// Base64 support: PBKDF2 uses a variant of standard unpadded Base64 which substitutes the `+`
// character for `.` and this is a distinct encoding from the bcrypt and crypt Base64 variants.

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
    use super::{Error, base64_decode};
    use crate::{Params, Pbkdf2};
    use mcf::PasswordHash;
    use password_hash::{CustomizedPasswordHasher, PasswordVerifier};

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

        let actual_hash: PasswordHash = Pbkdf2::SHA256
            .hash_password_with_params(EXAMPLE_PASSWORD, salt.as_slice(), params)
            .unwrap();

        let expected_hash = PasswordHash::new(EXAMPLE_HASH).unwrap();
        assert_eq!(expected_hash, actual_hash);

        assert_eq!(
            Pbkdf2::SHA256.verify_password(EXAMPLE_PASSWORD, &actual_hash),
            Ok(())
        );

        assert_eq!(
            Pbkdf2::SHA256.verify_password(b"bogus", &actual_hash),
            Err(Error::PasswordInvalid)
        );
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

        assert_eq!(
            Pbkdf2::SHA512.verify_password(EXAMPLE_PASSWORD, &actual_hash),
            Ok(())
        );

        assert_eq!(
            Pbkdf2::SHA512.verify_password(b"bogus", &actual_hash),
            Err(Error::PasswordInvalid)
        );
    }
}
