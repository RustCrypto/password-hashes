//! "Simple" API which uses the Modular Crypt Format (MCF).

#![cfg(feature = "simple")]

use crate::{
    CheckError, DecodeError, ROUNDS_DEFAULT, Sha256Params, Sha512Params,
    consts::{
        BLOCK_SIZE_SHA256, BLOCK_SIZE_SHA512, MAP_SHA256, MAP_SHA512, PW_SIZE_SHA256, SALT_MAX_LEN,
    },
    sha256_crypt, sha256_crypt_b64, sha512_crypt, sha512_crypt_b64,
};
use alloc::string::{String, ToString};
use base64ct::{Base64ShaCrypt, Encoding};
use rand_core::{OsRng, RngCore, TryRngCore};

const SHA256_MCF_ID: &str = "5";
const SHA512_MCF_ID: &str = "6";
const ROUNDS_PARAM: &str = "rounds=";

/// Simple interface for generating a SHA512 password hash.
///
/// The salt will be chosen randomly. The output format will conform to [1].
///
///  `$<ID>$<SALT>$<HASH>`
///
/// # Returns
/// - `Ok(String)` containing the full SHA512 password hash format on success
/// - `Err(CryptError)` if something went wrong.
///
/// [1]: https://www.akkadia.org/drepper/SHA-crypt.txt
pub fn sha512_simple(password: &str, params: &Sha512Params) -> String {
    let salt = random_salt();
    let out = sha512_crypt_b64(password.as_bytes(), salt.as_bytes(), params);

    let mut mcf_hash = mcf::PasswordHash::from_id(SHA512_MCF_ID).expect("should have valid ID");

    if params.rounds != ROUNDS_DEFAULT {
        mcf_hash
            .push_str(&format!("{}{}", ROUNDS_PARAM, params.rounds))
            .expect("should be valid field");
    }

    mcf_hash.push_str(&salt).expect("should have valid salt");
    mcf_hash.push_str(&out).expect("should have valid hash");

    mcf_hash.into()
}

/// Simple interface for generating a SHA256 password hash.
///
/// The salt will be chosen randomly. The output format will conform to [1].
///
///  `$<ID>$<SALT>$<HASH>`
///
/// # Returns
/// - `Ok(String)` containing the full SHA256 password hash format on success
/// - `Err(CryptError)` if something went wrong.
///
/// [1]: https://www.akkadia.org/drepper/SHA-crypt.txt
pub fn sha256_simple(password: &str, params: &Sha256Params) -> String {
    let salt = random_salt();
    let out = sha256_crypt_b64(password.as_bytes(), salt.as_bytes(), params);

    let mut mcf_hash = mcf::PasswordHash::from_id(SHA256_MCF_ID).expect("should have valid ID");

    if params.rounds != ROUNDS_DEFAULT {
        mcf_hash
            .push_str(&format!("{}{}", ROUNDS_PARAM, params.rounds))
            .expect("should be valid field");
    }

    mcf_hash.push_str(&salt).expect("should have valid salt");
    mcf_hash.push_str(&out).expect("should have valid hash");

    mcf_hash.into()
}

/// Checks that given password matches provided hash.
///
/// # Arguments
/// - `password` - expected password
/// - `hashed_value` - the hashed value which should be used for checking,
///   should be of format mentioned in [1]: `$6$<SALT>$<PWD>`
///
/// # Return
/// `OK(())` if password matches otherwise Err(CheckError) in case of invalid
/// format or password mismatch.
///
/// [1]: https://www.akkadia.org/drepper/SHA-crypt.txt
pub fn sha512_check(password: &str, hashed_value: &str) -> Result<(), CheckError> {
    let mut iter = hashed_value.split('$');

    // Check that there are no characters before the first "$"
    if iter.next() != Some("") {
        return Err(CheckError::InvalidFormat(
            "Should start with '$".to_string(),
        ));
    }

    if iter.next() != Some("6") {
        return Err(CheckError::InvalidFormat(format!(
            "does not contain SHA512 identifier: '${SHA512_MCF_ID}$'",
        )));
    }

    let mut next = iter.next().ok_or_else(|| {
        CheckError::InvalidFormat("Does not contain a rounds or salt nor hash string".to_string())
    })?;
    let rounds = if next.starts_with(ROUNDS_PARAM) {
        let rounds = next;
        next = iter.next().ok_or_else(|| {
            CheckError::InvalidFormat("Does not contain a salt nor hash string".to_string())
        })?;

        rounds[ROUNDS_PARAM.len()..].parse().map_err(|_| {
            CheckError::InvalidFormat(format!("{ROUNDS_PARAM} specifier need to be a number",))
        })?
    } else {
        ROUNDS_DEFAULT
    };

    let salt = next;

    let hash = iter
        .next()
        .ok_or_else(|| CheckError::InvalidFormat("Does not contain a hash string".to_string()))?;

    // Make sure there is no trailing data after the final "$"
    if iter.next().is_some() {
        return Err(CheckError::InvalidFormat(
            "Trailing characters present".to_string(),
        ));
    }

    let params = match Sha512Params::new(rounds) {
        Ok(p) => p,
        Err(e) => return Err(CheckError::Crypt(e)),
    };

    let output = sha512_crypt(password.as_bytes(), salt.as_bytes(), &params);

    let hash = decode_sha512(hash.as_bytes())?;

    use subtle::ConstantTimeEq;
    if output.ct_eq(&hash).into() {
        Ok(())
    } else {
        Err(CheckError::HashMismatch)
    }
}

/// Checks that given password matches provided hash.
///
/// # Arguments
/// - `password` - expected password
/// - `hashed_value` - the hashed value which should be used for checking,
///   should be of format mentioned in [1]: `$6$<SALT>$<PWD>`
///
/// # Return
/// `OK(())` if password matches otherwise Err(CheckError) in case of invalid
/// format or password mismatch.
///
/// [1]: https://www.akkadia.org/drepper/SHA-crypt.txt
pub fn sha256_check(password: &str, hashed_value: &str) -> Result<(), CheckError> {
    let mut iter = hashed_value.split('$');

    // Check that there are no characters before the first "$"
    if iter.next() != Some("") {
        return Err(CheckError::InvalidFormat(
            "Should start with '$".to_string(),
        ));
    }

    if iter.next() != Some("5") {
        return Err(CheckError::InvalidFormat(format!(
            "does not contain SHA256 identifier: '${SHA256_MCF_ID}$'",
        )));
    }

    let mut next = iter.next().ok_or_else(|| {
        CheckError::InvalidFormat("Does not contain a rounds or salt nor hash string".to_string())
    })?;
    let rounds = if next.starts_with(ROUNDS_PARAM) {
        let rounds = next;
        next = iter.next().ok_or_else(|| {
            CheckError::InvalidFormat("Does not contain a salt nor hash string".to_string())
        })?;

        rounds[ROUNDS_PARAM.len()..].parse().map_err(|_| {
            CheckError::InvalidFormat(format!("{ROUNDS_PARAM} specifier need to be a number",))
        })?
    } else {
        ROUNDS_DEFAULT
    };

    let salt = next;

    let hash = iter
        .next()
        .ok_or_else(|| CheckError::InvalidFormat("Does not contain a hash string".to_string()))?;

    // Make sure there is no trailing data after the final "$"
    if iter.next().is_some() {
        return Err(CheckError::InvalidFormat(
            "Trailing characters present".to_string(),
        ));
    }

    let params = match Sha256Params::new(rounds) {
        Ok(p) => p,
        Err(e) => return Err(CheckError::Crypt(e)),
    };

    let output = sha256_crypt(password.as_bytes(), salt.as_bytes(), &params);

    let hash = decode_sha256(hash.as_bytes())?;

    use subtle::ConstantTimeEq;
    if output.ct_eq(&hash).into() {
        Ok(())
    } else {
        Err(CheckError::HashMismatch)
    }
}

/// Generate a random salt that is 16-bytes long.
fn random_salt() -> String {
    // Create buffer containing raw bytes to encode as Base64
    let mut buf = [0u8; (SALT_MAX_LEN * 3).div_ceil(4)];
    OsRng.unwrap_err().fill_bytes(&mut buf);
    Base64ShaCrypt::encode_string(&buf)
}

fn decode_sha512(source: &[u8]) -> Result<[u8; BLOCK_SIZE_SHA512], DecodeError> {
    const BUF_SIZE: usize = 86;
    let mut buf = [0u8; BUF_SIZE];
    Base64ShaCrypt::decode(source, &mut buf).map_err(|_| DecodeError)?;
    let mut transposed = [0u8; BLOCK_SIZE_SHA512];
    for (i, &ti) in MAP_SHA512.iter().enumerate() {
        transposed[ti as usize] = buf[i];
    }
    Ok(transposed)
}

fn decode_sha256(source: &[u8]) -> Result<[u8; BLOCK_SIZE_SHA256], DecodeError> {
    let mut buf = [0u8; PW_SIZE_SHA256];
    Base64ShaCrypt::decode(source, &mut buf).unwrap();

    let mut transposed = [0u8; BLOCK_SIZE_SHA256];
    for (i, &ti) in MAP_SHA256.iter().enumerate() {
        transposed[ti as usize] = buf[i];
    }
    Ok(transposed)
}
