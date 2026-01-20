//! Implementation of the `password-hash` crate API.

pub use password_hash::phc::PasswordHash;

use crate::{Algorithm, Params, Pbkdf2, pbkdf2_hmac_with_params};
use password_hash::{
    CustomizedPasswordHasher, Error, PasswordHasher, Result,
    phc::{Output, Salt},
};

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

        let mut buffer = [0u8; Params::MAX_OUTPUT_LENGTH];
        let out = buffer
            .get_mut(..params.output_len())
            .ok_or(Error::OutputSize)?;

        pbkdf2_hmac_with_params(password, salt.as_ref(), algorithm, params, out);
        let output = Output::new(out)?;

        Ok(PasswordHash {
            algorithm: algorithm.into(),
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

#[cfg(test)]
mod tests {
    use super::PasswordHash;
    use crate::{Params, Pbkdf2};
    use hex_literal::hex;
    use password_hash::CustomizedPasswordHasher;

    const PASSWORD: &[u8] = b"passwordPASSWORDpassword";
    const SALT: &[u8] = b"saltSALTsaltSALTsaltSALTsaltSALTsalt";
    const EXPECTED_HASH: &str = "$pbkdf2-sha256$i=4096,l=40\
        $c2FsdFNBTFRzYWx0U0FMVHNhbHRTQUxUc2FsdFNBTFRzYWx0\
        $NIyJ28vTKy8y2BS4EW6EzysXNH68GAAYHE4qH7jdU+HGNVGMfaxH6Q";

    /// Test with `algorithm: None`: uses default PBKDF2-SHA256
    ///
    /// Input:
    /// - P = "passwordPASSWORDpassword" (24 octets)
    /// - S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
    /// - c = 4096
    /// - dkLen = 40
    #[test]
    fn hash_with_default_algorithm() {
        let params = Params::new_with_output_len(4096, 40).unwrap();

        let pwhash: PasswordHash = Pbkdf2::default()
            .hash_password_customized(PASSWORD, SALT, None, None, params)
            .unwrap();

        assert_eq!(
            pwhash.algorithm,
            crate::algorithm::Algorithm::Pbkdf2Sha256.into()
        );
        assert_eq!(pwhash.salt.unwrap().as_ref(), SALT);
        assert_eq!(Params::try_from(&pwhash).unwrap(), params);

        let expected_output = hex!(
            "34 8c 89 db cb d3 2b 2f
             32 d8 14 b8 11 6e 84 cf
             2b 17 34 7e bc 18 00 18
             1c 4e 2a 1f b8 dd 53 e1
             c6 35 51 8c 7d ac 47 e9 "
        );

        assert_eq!(pwhash.hash.unwrap().as_ref(), expected_output);
        assert_eq!(pwhash, EXPECTED_HASH.parse().unwrap());
    }
}
