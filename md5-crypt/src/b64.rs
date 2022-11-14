//! Base64 encoding support

use crate::defs::{BLOCK_SIZE, MAP_MD5, PW_SIZE_MD5};
#[cfg(any(feature = "subtle", test))]
use crate::errors::DecodeError;
use base64ct::{Base64ShaCrypt, Encoding};

pub fn encode_md5(source: &[u8]) -> [u8; PW_SIZE_MD5] {
    let mut transposed = [0u8; BLOCK_SIZE];
    for (i, &ti) in MAP_MD5.iter().enumerate() {
        transposed[i] = source[ti as usize];
    }
    let mut buf = [0u8; PW_SIZE_MD5];
    Base64ShaCrypt::encode(&transposed, &mut buf).unwrap();
    buf
}

#[cfg(any(feature = "subtle", test))]
pub fn decode_md5(source: &[u8]) -> Result<[u8; BLOCK_SIZE], DecodeError> {
    let mut buf = [0u8; PW_SIZE_MD5];
    Base64ShaCrypt::decode(source, &mut buf).map_err(|_| DecodeError)?;
    let mut transposed = [0u8; BLOCK_SIZE];
    for (i, &ti) in MAP_MD5.iter().enumerate() {
        transposed[ti as usize] = buf[i];
    }
    Ok(transposed)
}

mod tests {
    #[test]
    fn test_encode_decode_md5() {
        let original: [u8; 16] = [
            0x0b, 0x5b, 0xdf, 0x7d, 0x92, 0xe2, 0xfc, 0xbd, 0xab, 0x57, 0xcb, 0xf3, 0xe0, 0x03,
            0x16, 0x62,
        ];

        let e = super::encode_md5(&original);
        let d = super::decode_md5(&e).unwrap();

        for i in 0..d.len() {
            assert_eq!(&original[i], &d[i]);
        }
    }
}
