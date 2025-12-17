//! Implementation of the `password-hash` traits for Modular Crypt Format (MCF) password hash
//! strings which begin with `$7$`:
//!
//! <https://man.archlinux.org/man/crypt.5#scrypt>

pub use mcf::{PasswordHash, PasswordHashRef};

use crate::{Params, Scrypt, scrypt};
use alloc::{string::String, vec};
use core::str;
use mcf::Base64;
use password_hash::{
    CustomizedPasswordHasher, Error, PasswordHasher, PasswordVerifier, Result, Version,
};

/// Identifier for scrypt when encoding to the Modular Crypt Format, i.e. `$7$`
#[cfg(feature = "password-hash")]
const MCF_ID: &str = "7";

/// Base64 variant used by scrypt.
const SCRYPT_BASE64: Base64 = Base64::ShaCrypt;

/// Size of a `u32` when using scrypt's fixed-width Base64 encoding.
const ENCODED_U32_LEN: usize = 5;

/// Length of scrypt's params when encoded as binary: `log_n`: 1-byte, `r`/`p`: 5-bytes
const PARAMS_LEN: usize = 1 + (2 * ENCODED_U32_LEN);

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
        // TODO(tarcieri): tunable hash output size?
        const HASH_SIZE: usize = 32;

        match alg_id {
            Some(MCF_ID) | None => (),
            _ => return Err(Error::Algorithm),
        }

        if version.is_some() {
            return Err(Error::Version);
        }

        let params_and_salt = encode_params_and_salt(params, salt)?;

        // When used with MCF, the scrypt salt is Base64 encoded
        let salt = &params_and_salt.as_bytes()[PARAMS_LEN..];

        let mut out = [0u8; HASH_SIZE];
        scrypt(password, salt, &params, &mut out).map_err(|_| Error::OutputSize)?;

        // Begin building the Modular Crypt Format hash.
        let mut mcf_hash = PasswordHash::from_id(MCF_ID).expect("should be valid");

        // Add salt
        mcf_hash
            .push_str(&params_and_salt)
            .map_err(|_| Error::EncodingInvalid)?;

        // Add scrypt password hashing function output
        mcf_hash.push_base64(&out, SCRYPT_BASE64);

        Ok(mcf_hash)
    }
}

impl PasswordHasher<PasswordHash> for Scrypt {
    fn hash_password_with_salt(&self, password: &[u8], salt: &[u8]) -> Result<PasswordHash> {
        self.hash_password_customized(password, salt, None, None, Params::RECOMMENDED)
    }
}

impl PasswordVerifier<PasswordHash> for Scrypt {
    fn verify_password(&self, password: &[u8], hash: &PasswordHash) -> Result<()> {
        self.verify_password(password, hash.as_password_hash_ref())
    }
}

impl PasswordVerifier<PasswordHashRef> for Scrypt {
    fn verify_password(&self, password: &[u8], hash: &PasswordHashRef) -> Result<()> {
        // verify id matches `$7`
        if hash.id() != MCF_ID {
            return Err(Error::Algorithm);
        }

        let mut fields = hash.fields();

        // decode params and salt
        let (params, salt) =
            decode_params_and_salt(fields.next().ok_or(Error::EncodingInvalid)?.as_str())?;

        // decode expected password hash
        let expected = fields
            .next()
            .ok_or(Error::EncodingInvalid)?
            .decode_base64(SCRYPT_BASE64)
            .map_err(|_| Error::EncodingInvalid)?;

        // should be the last field
        if fields.next().is_some() {
            return Err(Error::EncodingInvalid);
        }

        let mut actual = vec![0u8; expected.len()];
        scrypt(password, salt, &params, &mut actual).map_err(|_| Error::OutputSize)?;

        if subtle::ConstantTimeEq::ct_ne(actual.as_slice(), &expected).into() {
            return Err(Error::PasswordInvalid);
        }

        Ok(())
    }
}

/// scrypt-flavored Base64 alphabet.
static ITOA64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Reverse lookup table for scrypt-flavored Base64 alphabet.
static ATOI64: [u8; 128] = {
    let mut tbl = [0xFFu8; 128]; // use 0xFF as a placeholder for invalid chars
    let mut i = 0u8;
    while i < 64 {
        tbl[ITOA64[i as usize] as usize] = i;
        i += 1;
    }
    tbl
};

/// Decode scrypt parameters and salt from the combined string they're encoded in.
fn decode_params_and_salt(s: &str) -> Result<(Params, &[u8])> {
    let bytes = s.as_bytes();

    if bytes.is_empty() {
        return Err(Error::EncodingInvalid);
    }

    // log_n
    let log_n = *ATOI64
        .get(bytes[0] as usize)
        .ok_or(Error::EncodingInvalid)?;

    let mut pos = 1;

    // r
    let r = decode64_uint32(&bytes[pos..])?;
    pos += ENCODED_U32_LEN;

    // p
    let p = decode64_uint32(&bytes[pos..])?;
    pos += ENCODED_U32_LEN;

    let params = Params::new(log_n, r, p).map_err(|_| Error::ParamsInvalid)?;

    Ok((params, &s.as_bytes()[pos..]))
}

/// Encode scrypt parameters and salt into scrypt-flavored Base64.
fn encode_params_and_salt(params: Params, salt: &[u8]) -> Result<String> {
    let mut buf = [0u8; PARAMS_LEN];
    let params_base64 = encode_params(params, &mut buf)?;

    let mut ret = String::from(params_base64);
    ret.push_str(&SCRYPT_BASE64.encode_string(salt));
    Ok(ret)
}

/// Encode params as scrypt-flavored Base64 to the given output buffer.
fn encode_params(params: Params, out: &mut [u8]) -> Result<&str> {
    // encode log_n (uses a special 1-byte encoding)
    let encoded_log_n = *ITOA64
        .get(params.log_n as usize)
        .ok_or(Error::EncodingInvalid)?;

    *out.get_mut(0).ok_or(Error::EncodingInvalid)? = encoded_log_n;

    let mut pos = 1;

    // encode r
    encode64_uint32(&mut out[pos..], params.r())?;
    pos += ENCODED_U32_LEN;

    // encode p
    encode64_uint32(&mut out[pos..], params.p())?;
    pos += ENCODED_U32_LEN;

    str::from_utf8(&out[..pos]).map_err(|_| Error::EncodingInvalid)
}

/// Decode 32-bit integer value from Base64.
///
/// Uses a fixed-width little endian encoding.
fn decode64_uint32(src: &[u8]) -> Result<u32> {
    let mut value: u32 = 0;

    for i in 0..ENCODED_U32_LEN {
        let n = *src
            .get(i)
            .and_then(|&b| ATOI64.get(b as usize).filter(|&&n| n <= 63))
            .ok_or(Error::EncodingInvalid)?;

        value |= u32::from(n) << (6 * i);
    }

    Ok(value)
}

/// Encode 32-bit integer value from Base64.
///
/// Uses a fixed-width little endian encoding.
fn encode64_uint32(dst: &mut [u8], mut src: u32) -> Result<()> {
    if dst.len() < 5 {
        return Err(Error::EncodingInvalid);
    }

    #[allow(clippy::needless_range_loop)]
    for i in 0..ENCODED_U32_LEN {
        dst[i] = ITOA64[(src & 0x3f) as usize];
        src >>= 6;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CustomizedPasswordHasher, Error, Params, PasswordHash, PasswordHashRef, PasswordVerifier,
        SCRYPT_BASE64, Scrypt, decode_params_and_salt,
    };

    /// Password used to make the example MCF hash.
    const EXAMPLE_PASSWORD: &[u8] = b"pleaseletmein";

    /// Salt used to generate the hash, encoded as Base64.
    const EXAMPLE_SALT: &str = "Mq4YHD2syxYT.MsH1Ek0n1";

    /// Generated using `mkpasswd --method=scrypt`
    const EXAMPLE_MCF_HASH: &str =
        "$7$CU..../....Mq4YHD2syxYT.MsH1Ek0n1$JyHIxez0DOwm0r6.kAIohc8UFBOLU4xX8a1wGBpLrw7";

    // libxcrypt defaults: https://github.com/besser82/libxcrypt/blob/a74a677/lib/crypt-scrypt.c#L213-L215
    // TODO(tarcieri): const constructor for `Params`
    const EXAMPLE_LOG_N: u8 = 14; // count = 7; count + 7 (L215)
    const EXAMPLE_R: u32 = 32; // uint32_t r = 32; (L214)
    const EXAMPLE_P: u32 = 1; // uint32_t p = 1; (L213)

    #[test]
    fn params_and_salt_decoder() {
        let mut mcf_iter = EXAMPLE_MCF_HASH.split('$');
        mcf_iter.next().unwrap();
        mcf_iter.next().unwrap();

        let params_and_salt = mcf_iter.next().unwrap();
        let (params, salt) = decode_params_and_salt(params_and_salt).unwrap();

        assert_eq!(params.p(), EXAMPLE_P);
        assert_eq!(params.r(), EXAMPLE_R);
        assert_eq!(params.log_n(), EXAMPLE_LOG_N);

        assert_eq!(salt, EXAMPLE_SALT.as_bytes());
    }

    #[test]
    fn hash_password() {
        let salt = SCRYPT_BASE64.decode_vec(EXAMPLE_SALT).unwrap();
        let params = Params::new(EXAMPLE_LOG_N, EXAMPLE_R, EXAMPLE_P).unwrap();

        let actual_hash: PasswordHash = Scrypt
            .hash_password_with_params(EXAMPLE_PASSWORD, &salt, params)
            .unwrap();

        let expected_hash = PasswordHash::new(EXAMPLE_MCF_HASH).unwrap();
        assert_eq!(expected_hash, actual_hash);
    }

    #[test]
    fn verify_password() {
        let hash = PasswordHashRef::new(EXAMPLE_MCF_HASH).unwrap();
        assert_eq!(Scrypt.verify_password(EXAMPLE_PASSWORD, hash), Ok(()));

        assert_eq!(
            Scrypt.verify_password(b"bogus", hash),
            Err(Error::PasswordInvalid)
        );
    }
}
