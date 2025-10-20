//! Base64 encoding support

#![cfg(feature = "simple")]

use crate::{
    consts::{BLOCK_SIZE_SHA256, BLOCK_SIZE_SHA512, MAP_SHA256, MAP_SHA512, PW_SIZE_SHA256},
    errors::DecodeError,
};
use base64ct::{Base64ShaCrypt, Encoding};

pub fn decode_sha512(source: &[u8]) -> Result<[u8; BLOCK_SIZE_SHA512], DecodeError> {
    const BUF_SIZE: usize = 86;
    let mut buf = [0u8; BUF_SIZE];
    Base64ShaCrypt::decode(source, &mut buf).map_err(|_| DecodeError)?;
    let mut transposed = [0u8; BLOCK_SIZE_SHA512];
    for (i, &ti) in MAP_SHA512.iter().enumerate() {
        transposed[ti as usize] = buf[i];
    }
    Ok(transposed)
}

pub fn decode_sha256(source: &[u8]) -> Result<[u8; BLOCK_SIZE_SHA256], DecodeError> {
    let mut buf = [0u8; PW_SIZE_SHA256];
    Base64ShaCrypt::decode(source, &mut buf).unwrap();

    let mut transposed = [0u8; BLOCK_SIZE_SHA256];
    for (i, &ti) in MAP_SHA256.iter().enumerate() {
        transposed[ti as usize] = buf[i];
    }
    Ok(transposed)
}
