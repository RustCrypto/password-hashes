//! Base64 encoding support

use crate::defs::{BLOCK_SIZE, MAP_SHA512, PW_SIZE_SHA512};
use alloc::vec::Vec;
use base64ct::{Base64ShaCrypt, Encoding};


#[cfg(feature = "simple")]
use crate::errors::DecodeError;

pub fn encode_sha512(source: &[u8]) -> Vec<u8> {
    const BUF_SIZE: usize = PW_SIZE_SHA512;
    let mut transposed = [0u8; BLOCK_SIZE];
    for (i, &ti) in MAP_SHA512.iter().enumerate() {
        transposed[i] = source[ti as usize];
    }
    let mut buf = [0u8; BUF_SIZE];
    Base64ShaCrypt::encode(&transposed, &mut buf).unwrap();
    buf.to_vec()
}

#[cfg(feature = "simple")]
pub fn decode_sha512(source: &[u8]) -> Result<Vec<u8>, DecodeError> {
    const BUF_SIZE: usize = 86;
    let mut buf = [0u8; BUF_SIZE];
    Base64ShaCrypt::decode(&source, &mut buf).map_err(|_| DecodeError)?;

    let mut transposed = [0u8; BLOCK_SIZE];
    for (i, &ti) in MAP_SHA512.iter().enumerate() {
        transposed[ti as usize] = buf[i];
    }
    Ok(transposed.to_vec())
}

mod tests {
    #[cfg(feature = "simple")]
    #[test]
    fn test_encode_decode_sha512() {
        let original: [u8; 64] = [
            0x0b, 0x5b, 0xdf, 0x7d, 0x92, 0xe2, 0xfc, 0xbd, 0xab, 0x57, 0xcb, 0xf3, 0xe0, 0x03,
            0x16, 0x62, 0xd3, 0x6e, 0xa0, 0x57, 0x44, 0x8c, 0xca, 0x35, 0xec, 0x80, 0x75, 0x2a,
            0x37, 0xd4, 0xe6, 0xfa, 0xf7, 0xd7, 0x78, 0xf4, 0x8e, 0x0b, 0x3e, 0xab, 0x23, 0x05,
            0x15, 0xdd, 0x79, 0x14, 0x45, 0xac, 0x66, 0x60, 0x25, 0x94, 0x97, 0x5e, 0x0f, 0x7f,
            0x5f, 0xaf, 0x1a, 0xe5, 0x08, 0xe7, 0x7d, 0xd4,
        ];

        let e = super::encode_sha512(&original);
        let d = super::decode_sha512(&e).unwrap();

        for i in 0..d.len() {
            assert_eq!(&original[i], &d[i]);
        }
    }
}
