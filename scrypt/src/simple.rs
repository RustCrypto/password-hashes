//! Implementation of the `password-hash` crate API.

use crate::{scrypt, Params};
use base64ct::{Base64, Encoding};
use core::convert::TryInto;
use password_hash::{Error, Ident, McfHasher, Output, PasswordHash, PasswordHasher, Result, Salt};

/// Algorithm identifier
pub const ALG_ID: Ident = Ident::new("scrypt");

/// scrypt type for use with [`PasswordHasher`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(docsrs, doc(cfg(feature = "simple")))]
pub struct Scrypt;

impl PasswordHasher for Scrypt {
    type Params = Params;

    fn hash_password<'a>(
        &self,
        password: &[u8],
        alg_id: Option<Ident<'a>>,
        params: Params,
        salt: impl Into<Salt<'a>>,
    ) -> Result<PasswordHash<'a>> {
        match alg_id {
            Some(ALG_ID) | None => (),
            _ => return Err(Error::Algorithm),
        }

        let salt = salt.into();
        let mut salt_arr = [0u8; 64];
        let salt_bytes = salt.b64_decode(&mut salt_arr)?;

        let output = Output::init_with(params.len, |out| {
            scrypt(password, &salt_bytes, &params, out).map_err(|_e| {
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

impl McfHasher for Scrypt {
    fn upgrade_mcf_hash<'a>(&self, hash: &'a str) -> Result<PasswordHash<'a>> {
        let mut parts = hash.split('$');

        let buf = [
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ];

        let (log_n, r, p, salt, hash) = match buf {
            [Some(""), Some("rscrypt"), Some("0"), Some(p), Some(s), Some(h), Some(""), None] => {
                let pvec = Base64::decode_vec(p)?;
                if pvec.len() != 3 {
                    return Err(Error::ParamValueInvalid);
                }
                (pvec[0], pvec[1] as u32, pvec[2] as u32, s, h)
            }
            [Some(""), Some("rscrypt"), Some("1"), Some(p), Some(s), Some(h), Some(""), None] => {
                let pvec = Base64::decode_vec(p)?;
                if pvec.len() != 9 {
                    return Err(Error::ParamValueInvalid);
                }
                let log_n = pvec[0];
                let r = u32::from_le_bytes(pvec[1..5].try_into().unwrap());
                let p = u32::from_le_bytes(pvec[5..9].try_into().unwrap());
                (log_n, r, p, s, h)
            }
            _ => return Err(Error::ParamValueInvalid),
        };

        let params = Params::new(log_n, r, p).map_err(|_| Error::ParamValueInvalid)?;
        let salt = Salt::new(b64_strip(salt))?;
        let hash = Output::b64_decode(b64_strip(hash))?;

        Ok(PasswordHash {
            algorithm: ALG_ID,
            version: None,
            params: params.try_into()?,
            salt: Some(salt),
            hash: Some(hash),
        })
    }
}

/// Strip trailing `=` signs off a Base64 value to make a valid B64 value
pub fn b64_strip(mut s: &str) -> &str {
    while s.ends_with('=') {
        s = &s[..(s.len() - 1)]
    }
    s
}
