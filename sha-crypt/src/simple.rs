//! Implementation of the `password-hash` crate API.

use crate::{
    BLOCK_SIZE_SHA256, BLOCK_SIZE_SHA512, ROUNDS_DEFAULT, Sha256Params, Sha512Params,
    consts::{MAP_SHA256, MAP_SHA512},
    sha256_crypt, sha512_crypt,
};
use base64ct::{Base64ShaCrypt, Encoding};
use core::marker::PhantomData;
use mcf::{Base64, PasswordHash, PasswordHashRef};
use password_hash::{
    CustomizedPasswordHasher, Error, PasswordHasher, PasswordVerifier, Result, Version,
};
use sha2::{Digest, Sha256, Sha512};

const SHA256_MCF_ID: &str = "5";
const SHA512_MCF_ID: &str = "6";
const ROUNDS_PARAM: &str = "rounds=";

/// sha-crypt type for use with [`PasswordHasher`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ShaCrypt<D: Digest> {
    phantom: PhantomData<D>,
}

/// SHA-crypt initialized using SHA-256
pub const SHA256_CRYPT: ShaCrypt<Sha256> = ShaCrypt {
    phantom: PhantomData,
};

/// SHA-crypt initialized using SHA-512
pub const SHA512_CRYPT: ShaCrypt<Sha512> = ShaCrypt {
    phantom: PhantomData,
};

impl CustomizedPasswordHasher<PasswordHash> for ShaCrypt<Sha256> {
    type Params = Sha256Params;

    fn hash_password_customized(
        &self,
        password: &[u8],
        salt: &[u8],
        alg_id: Option<&str>,
        version: Option<Version>,
        params: Sha256Params,
    ) -> Result<PasswordHash> {
        match alg_id {
            Some(SHA256_MCF_ID) | None => (),
            _ => return Err(Error::Algorithm),
        }

        if version.is_some() {
            return Err(Error::Version);
        }

        // We compute the function over the Base64-encoded salt
        let salt = Base64ShaCrypt::encode_string(salt);
        let out = sha256_crypt_transposed(password, salt.as_bytes(), &params);

        let mut mcf_hash = PasswordHash::from_id(SHA256_MCF_ID).expect("should have valid ID");

        if params.rounds != ROUNDS_DEFAULT {
            mcf_hash
                .push_str(&format!("{}{}", ROUNDS_PARAM, params.rounds))
                .expect("should be valid field");
        }

        mcf_hash
            .push_str(&salt)
            .map_err(|_| Error::EncodingInvalid)?;
        mcf_hash.push_base64(&out, Base64::ShaCrypt);
        Ok(mcf_hash)
    }
}

impl CustomizedPasswordHasher<PasswordHash> for ShaCrypt<Sha512> {
    type Params = Sha512Params;

    fn hash_password_customized(
        &self,
        password: &[u8],
        salt: &[u8],
        alg_id: Option<&str>,
        version: Option<Version>,
        params: Sha512Params,
    ) -> Result<PasswordHash> {
        match alg_id {
            Some(SHA512_MCF_ID) | None => (),
            _ => return Err(Error::Algorithm),
        }

        if version.is_some() {
            return Err(Error::Version);
        }

        // We compute the function over the Base64-encoded salt
        let salt = Base64ShaCrypt::encode_string(salt);
        let out = sha512_crypt_transposed(password, salt.as_bytes(), &params);

        let mut mcf_hash = PasswordHash::from_id(SHA512_MCF_ID).expect("should have valid ID");

        if params.rounds != ROUNDS_DEFAULT {
            mcf_hash
                .push_str(&format!("{}{}", ROUNDS_PARAM, params.rounds))
                .expect("should be valid field");
        }

        mcf_hash
            .push_str(&salt)
            .map_err(|_| Error::EncodingInvalid)?;
        mcf_hash.push_base64(&out, Base64::ShaCrypt);
        Ok(mcf_hash)
    }
}

impl PasswordHasher<PasswordHash> for ShaCrypt<Sha256> {
    fn hash_password_with_salt(&self, password: &[u8], salt: &[u8]) -> Result<PasswordHash> {
        self.hash_password_customized(password, salt, None, None, Sha256Params::default())
    }
}

impl PasswordHasher<PasswordHash> for ShaCrypt<Sha512> {
    fn hash_password_with_salt(&self, password: &[u8], salt: &[u8]) -> Result<PasswordHash> {
        self.hash_password_customized(password, salt, None, None, Sha512Params::default())
    }
}

impl PasswordVerifier<PasswordHash> for ShaCrypt<Sha256> {
    fn verify_password(&self, password: &[u8], hash: &PasswordHash) -> Result<()> {
        self.verify_password(password, hash.as_password_hash_ref())
    }
}

impl PasswordVerifier<PasswordHash> for ShaCrypt<Sha512> {
    fn verify_password(&self, password: &[u8], hash: &PasswordHash) -> Result<()> {
        self.verify_password(password, hash.as_password_hash_ref())
    }
}

impl PasswordVerifier<PasswordHashRef> for ShaCrypt<Sha256> {
    fn verify_password(&self, password: &[u8], hash: &PasswordHashRef) -> Result<()> {
        // verify id matches `$6`
        if hash.id() != SHA256_MCF_ID {
            return Err(Error::Algorithm);
        }

        let mut fields = hash.fields();
        let mut next = fields.next().ok_or(Error::EncodingInvalid)?;

        let mut params = Sha256Params::default();

        // decode params
        // TODO(tarcieri): `mcf::Field` helper methods for parsing params?
        if let Some(rounds_str) = next.as_str().strip_prefix(ROUNDS_PARAM) {
            let rounds = rounds_str.parse().map_err(|_| Error::EncodingInvalid)?;
            params = Sha256Params::new(rounds)?;
            next = fields.next().ok_or(Error::EncodingInvalid)?;
        }

        let salt = next.as_str().as_bytes();

        // decode expected password hash
        let expected = fields
            .next()
            .ok_or(Error::EncodingInvalid)?
            .decode_base64(Base64::ShaCrypt)
            .map_err(|_| Error::EncodingInvalid)?;

        // should be the last field
        if fields.next().is_some() {
            return Err(Error::EncodingInvalid);
        }

        let actual = sha256_crypt_transposed(password, salt, &params);

        if subtle::ConstantTimeEq::ct_ne(actual.as_slice(), &expected).into() {
            return Err(Error::PasswordInvalid);
        }

        Ok(())
    }
}

impl PasswordVerifier<PasswordHashRef> for ShaCrypt<Sha512> {
    fn verify_password(&self, password: &[u8], hash: &PasswordHashRef) -> Result<()> {
        // verify id matches `$6`
        if hash.id() != SHA512_MCF_ID {
            return Err(Error::Algorithm);
        }

        let mut fields = hash.fields();
        let mut next = fields.next().ok_or(Error::EncodingInvalid)?;

        let mut params = Sha512Params::default();

        // decode params
        // TODO(tarcieri): `mcf::Field` helper methods for parsing params?
        if let Some(rounds_str) = next.as_str().strip_prefix(ROUNDS_PARAM) {
            let rounds = rounds_str.parse().map_err(|_| Error::EncodingInvalid)?;
            params = Sha512Params::new(rounds)?;
            next = fields.next().ok_or(Error::EncodingInvalid)?;
        }

        let salt = next.as_str().as_bytes();

        // decode expected password hash
        let expected = fields
            .next()
            .ok_or(Error::EncodingInvalid)?
            .decode_base64(Base64::ShaCrypt)
            .map_err(|_| Error::EncodingInvalid)?;

        // should be the last field
        if fields.next().is_some() {
            return Err(Error::EncodingInvalid);
        }

        let actual = sha512_crypt_transposed(password, salt, &params);

        if subtle::ConstantTimeEq::ct_ne(actual.as_slice(), &expected).into() {
            return Err(Error::PasswordInvalid);
        }

        Ok(())
    }
}

/// Invokes sha256_crypt then runs the result through the SHA-256-specific transposition table.
fn sha256_crypt_transposed(
    password: &[u8],
    salt: &[u8],
    params: &Sha256Params,
) -> [u8; BLOCK_SIZE_SHA256] {
    let output = sha256_crypt(password, salt, params);

    let mut transposed = [0u8; BLOCK_SIZE_SHA256];
    for (i, &ti) in MAP_SHA256.iter().enumerate() {
        transposed[i] = output[ti as usize];
    }

    transposed
}

/// Invokes sha512_crypt then runs the result through the SHA-512-specific transposition table.
fn sha512_crypt_transposed(
    password: &[u8],
    salt: &[u8],
    params: &Sha512Params,
) -> [u8; BLOCK_SIZE_SHA512] {
    let output = sha512_crypt(password, salt, params);

    let mut transposed = [0u8; BLOCK_SIZE_SHA512];
    for (i, &ti) in MAP_SHA512.iter().enumerate() {
        transposed[i] = output[ti as usize];
    }

    transposed
}
