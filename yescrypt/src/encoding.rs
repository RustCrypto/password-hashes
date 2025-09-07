//! Support for encoding (s)crypt-flavored Base64.
// TODO(tarcieri): use `base64ct` instead?

use crate::{Error, Result};
use core::str;

/// (s)crypt-flavored Base64 alphabet.
static ITOA64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

pub(crate) fn encode64_uint32(dst: &mut [u8], mut src: u32, min: u32) -> Result<usize> {
    let mut start = 0u32;
    let mut end = 47u32;
    let mut chars = 1u32;
    let mut bits = 0u32;

    if src < min {
        return Err(Error);
    }

    src -= min;

    loop {
        let count = (end + 1 - start) << bits;
        if src < count {
            break;
        }
        if start >= 63 {
            return Err(Error);
        }
        start = end + 1;
        end = start + (62 - end) / 2;
        src -= count;
        chars += 1;
        bits += 6;
    }

    if dst.len() < (chars as usize) {
        return Err(Error);
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

/// Encode (s)crypt-flavored Base64, using the provided `buf` for storing output.
pub(crate) fn encode64<'a>(src: &[u8], buf: &'a mut [u8]) -> Result<&'a str> {
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
        let dnext = encode64_uint32_fixed(&mut buf[pos..], value, bits)?;
        pos += dnext;
    }

    str::from_utf8(&buf[..pos]).map_err(|_| Error)
}

fn encode64_uint32_fixed(dst: &mut [u8], mut src: u32, srcbits: u32) -> Result<usize> {
    let mut bits: u32 = 0;
    let mut pos = 0;

    while bits < srcbits {
        if dst.len() <= pos {
            return Err(Error);
        }

        dst[pos] = ITOA64[(src & 0x3f) as usize];
        pos += 1;
        src >>= 6;
        bits += 6;
    }

    if src != 0 || dst.len() < pos {
        return Err(Error);
    }

    Ok(pos)
}
