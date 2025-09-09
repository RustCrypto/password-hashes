//! Support for encoding (s)crypt-flavored Base64.
// TODO(tarcieri): use `base64ct` instead?

use crate::{Error, Result};

#[cfg(feature = "simple")]
use core::str;

/// (s)crypt-flavored Base64 alphabet.
static ITOA64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Reverse lookup table for (s)crypt-flavored Base64 alphabet.
pub const ATOI64: [u8; 128] = {
    let mut tbl = [0xFFu8; 128]; // use 0xFF as a placeholder for invalid chars
    let mut i = 0;
    while i < 64 {
        tbl[ITOA64[i] as usize] = i as u8;
        i += 1;
    }
    tbl
};

#[cfg(feature = "simple")]
pub(crate) fn decode64<'o>(src: &str, dst: &'o mut [u8]) -> Result<&'o [u8]> {
    let src = src.as_bytes();
    let mut pos = 0usize;
    let mut i = 0usize;

    while i < src.len() {
        let mut value = 0u32;
        let mut bits = 0u32;

        while bits < 24 && i < src.len() {
            let c = match ATOI64.get(src[i] as usize) {
                Some(&c) if c <= 63 => c,
                _ => return Err(Error::Encoding),
            };

            value |= (c as u32) << bits;
            bits += 6;
            i += 1;
        }

        // must have at least one full byte
        if bits < 12 {
            return Err(Error::Encoding);
        }

        while pos < dst.len() {
            dst[pos] = value as u8;
            pos += 1;
            value >>= 8;
            bits -= 8;
            if bits < 8 {
                if value != 0 {
                    // 2 or 4
                    return Err(Error::Encoding);
                }
                break;
            }
        }
    }

    Ok(&dst[..pos])
}

pub(crate) fn decode64_uint32(src: &[u8], mut pos: usize, min: u32) -> Result<(u32, usize)> {
    let mut start = 0u32;
    let mut end = 47u32;
    let mut chars = 1u32;
    let mut bits = 0u32;

    if pos >= src.len() {
        return Err(Error::Encoding);
    }

    let c = match ATOI64.get(src[pos] as usize) {
        Some(&c) if c <= 63 => c,
        _ => return Err(Error::Encoding),
    };
    pos += 1;

    let mut dst = min;
    while c as u32 > end {
        dst += (end + 1 - start) << bits;
        start = end + 1;
        end = start + (62 - end) / 2;
        chars += 1;
        bits += 6;
    }

    dst += ((c as u32) - start) << bits;

    while chars > 1 {
        chars -= 1;

        if bits < 6 || pos >= src.len() {
            return Err(Error::Encoding);
        }

        let c = match ATOI64.get(src[pos] as usize) {
            Some(&c) if c <= 63 => c,
            _ => return Err(Error::Encoding),
        };
        pos += 1;

        bits -= 6;
        dst += (c as u32) << bits;
    }

    Ok((dst, pos))
}

#[cfg(feature = "simple")]
pub(crate) fn encode64<'o>(src: &[u8], out: &'o mut [u8]) -> Result<&'o str> {
    fn encode64_uint32_fixed(dst: &mut [u8], mut src: u32, srcbits: u32) -> Result<usize> {
        let mut bits: u32 = 0;
        let mut pos = 0;

        while bits < srcbits {
            if dst.len() <= pos {
                return Err(Error::Encoding);
            }

            dst[pos] = ITOA64[(src & 0x3f) as usize];
            pos += 1;
            src >>= 6;
            bits += 6;
        }

        if src != 0 || dst.len() < pos {
            return Err(Error::Encoding);
        }

        Ok(pos)
    }

    let mut pos = 0;
    let mut i = 0;

    while i < src.len() {
        let mut value = 0u32;
        let mut bits = 0u32;
        while bits < 24 && i < src.len() {
            value |= (src[i] as u32) << bits;
            bits += 8;
            i += 1;
        }
        let dnext = encode64_uint32_fixed(&mut out[pos..], value, bits)?;
        pos += dnext;
    }

    str::from_utf8(&out[..pos]).map_err(|_| Error::Encoding)
}

pub(crate) fn encode64_uint32(dst: &mut [u8], mut src: u32, min: u32) -> Result<usize> {
    let mut start = 0u32;
    let mut end = 47u32;
    let mut chars = 1u32;
    let mut bits = 0u32;

    if src < min {
        return Err(Error::Params);
    }

    src -= min;

    loop {
        let count = (end + 1 - start) << bits;
        if src < count {
            break;
        }
        if start >= 63 {
            return Err(Error::Encoding);
        }
        start = end + 1;
        end = start + (62 - end) / 2;
        src -= count;
        chars += 1;
        bits += 6;
    }

    if dst.len() < (chars as usize) {
        return Err(Error::Encoding);
    }

    let mut pos: usize = 0;
    dst[pos] = ITOA64[(start + (src >> bits)) as usize];
    pos += 1;

    while chars > 1 {
        chars -= 1;
        bits = bits.wrapping_sub(6);
        dst[pos] = ITOA64[((src >> bits) & 0x3f) as usize];
        pos += 1;
    }

    Ok(pos)
}
