//! Base64 encoding support

use crate::defs::{BLOCK_SIZE_SHA256, BLOCK_SIZE_SHA512, MAP_SHA256, MAP_SHA512, TAB};
use alloc::vec::Vec;

#[cfg(feature = "simple")]
use crate::errors::DecodeError;

pub fn encode_sha512(source: &[u8]) -> Vec<u8> {
    encode(source, MAP_SHA512)
}

pub fn encode_sha256(source: &[u8]) -> Vec<u8> {
    encode(source, MAP_SHA256)
}

fn encode<const N: usize>(source: &[u8], map: [(u8, u8, u8, u8); N]) -> Vec<u8> {
    let mut out: Vec<u8> = vec![];
    for entry in map {
        let mut w: usize = 0;
        if entry.3 > 2 {
            w |= source[entry.2 as usize] as usize;
            w <<= 8;
            w |= source[entry.1 as usize] as usize;
            w <<= 8;
        }
        w |= source[entry.0 as usize] as usize;

        for _ in 0..entry.3 {
            out.push(TAB[(w & 0x3f) as usize]);
            w >>= 6;
        }
    }
    out
}

#[cfg(feature = "simple")]
pub fn decode_sha512(source: &[u8]) -> Result<Vec<u8>, DecodeError> {
    decode::<22, BLOCK_SIZE_SHA512>(source, MAP_SHA512)
}

#[cfg(feature = "simple")]
pub fn decode_sha256(source: &[u8]) -> Result<Vec<u8>, DecodeError> {
    decode::<11, BLOCK_SIZE_SHA256>(source, MAP_SHA256)
}

#[cfg(feature = "simple")]
pub fn decode<const N: usize, const BLOCK_SIZE: usize>(source: &[u8], map : [(u8, u8, u8, u8); N]) -> Result<Vec<u8>, DecodeError> {
    let mut out: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];

    for iter in map.iter().enumerate() {
        let (i, entry) = iter;

        let mut w: usize = 0;

        for k in (0..entry.3).rev() {
            let byte = source.get(i * 4 + k as usize).ok_or(DecodeError)?;
            let pos = TAB.iter().position(|x| x == byte).ok_or(DecodeError)?;
            w <<= 6;
            w |= pos as usize;
        }

        out[entry.0 as usize] = (w & 0xff) as u8;
        w >>= 8;

        if entry.3 > 2 {
            out[entry.1 as usize] = (w & 0xff) as u8;
            w >>= 8;
            out[entry.2 as usize] = (w & 0xff) as u8;
        }
    }

    Ok(out.to_vec())
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

    #[cfg(feature = "simple")]
    #[test]
    fn test_encode_decode_sha256() {
        let original: [u8; 32] = [
            0x0b, 0x5b, 0xdf, 0x7d, 0x92, 0xe2, 0xfc, 0xbd, 0xab, 0x57, 0xcb, 0xf3, 0xe0, 0x03,
            0x16, 0x62, 0xd3, 0x6e, 0xa0, 0x57, 0x44, 0x8c, 0xca, 0x35, 0xec, 0x80, 0x75, 0x2a,
            0x5f, 0xaf, 0x1a, 0xe5
        ];

        let e = super::encode_sha256(&original);
        let d = super::decode_sha256(&e).unwrap();

        for i in 0..d.len() {
            assert_eq!(&original[i], &d[i]);
        }
    }
}
