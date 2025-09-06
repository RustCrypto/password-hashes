//! Support for encoding yescrypt parameters as (s)crypt-flavored Base64.
//!
//! Notably the parameter encoding uses Base64 over variable-width integers, with a "LEB"-style
//! variable-width integer encoding.

#![allow(non_snake_case)]

use crate::{Error, Flags, Params, Result};
use core::str;

/// (s)crypt-flavored Base64 alphabet.
// TODO(tarcieri): use `base64ct` instead?
static ITOA64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

impl Params {
    /// Maximum length of params when encoded as Base64: up to 8 params of up to 6 chars each.
    pub const MAX_ENCODED_LEN: usize = 8 * 6;

    /// Encode params as (s)crypt-flavored Base64.
    pub fn encode<'o>(&self, out: &'o mut [u8]) -> Result<&'o str> {
        let flavor = if self.flags.bits() < Flags::RW.bits() {
            self.flags.bits()
        } else if (self.flags & Flags::MODE_MASK) == Flags::RW
            && self.flags.bits() <= (Flags::RW | Flags::RW_FLAVOR_MASK).bits()
        {
            Flags::RW.bits() + (self.flags.bits() >> 2)
        } else {
            return Err(Error);
        };

        let N_log2 = N2log2(self.n);
        if N_log2 == 0 {
            return Err(Error);
        }

        let NROM_log2 = N2log2(self.nrom);
        if self.nrom != 0 && NROM_log2 == 0 {
            return Err(Error);
        }

        if (self.r as u64) * (self.p as u64) >= (1 << 30) {
            return Err(Error);
        }

        let mut pos = 0;

        // encode flavor
        let written = encode64_uint32(&mut out[pos..], flavor, 0)?;
        pos += written;

        // encode N_log2
        let written = encode64_uint32(&mut out[pos..], N_log2, 1)?;
        pos += written;

        // encode r
        let written = encode64_uint32(&mut out[pos..], self.r, 1)?;
        pos += written;

        let mut have = 0;
        if self.p != 1 {
            have |= 1;
        }
        if self.t != 0 {
            have |= 2;
        }
        if self.g != 0 {
            have |= 4;
        }
        if NROM_log2 != 0 {
            have |= 8;
        }

        if have != 0 {
            let written = encode64_uint32(&mut out[pos..], have, 1)?;
            pos += written;
        }

        if self.p != 1 {
            let written = encode64_uint32(&mut out[pos..], self.p, 2)?;
            pos += written;
        }

        if self.t != 0 {
            let written = encode64_uint32(&mut out[pos..], self.t, 1)?;
            pos += written;
        }

        if self.g != 0 {
            let written = encode64_uint32(&mut out[pos..], self.g, 1)?;
            pos += written;
        }

        if NROM_log2 != 0 {
            let written = encode64_uint32(&mut out[pos..], NROM_log2, 1)?;
            pos += written;
        }

        str::from_utf8(&out[..pos]).map_err(|_| Error)
    }
}

fn encode64_uint32(dst: &mut [u8], mut src: u32, min: u32) -> Result<usize> {
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

fn N2log2(N: u64) -> u32 {
    if N < 2 {
        return 0;
    }

    let mut N_log2 = 2u32;
    while (N >> N_log2) != 0 {
        N_log2 += 1;
    }
    N_log2 -= 1;

    if (N >> N_log2) != 1 {
        return 0;
    }

    N_log2
}

#[cfg(test)]
mod tests {
    use crate::{Flags, Params};

    #[test]
    fn params_encoder() {
        let mut buf = [0u8; Params::MAX_ENCODED_LEN];

        let p1 = Params {
            flags: Flags::default(),
            n: 4096,
            r: 32,
            p: 1,
            t: 0,
            g: 0,
            nrom: 0,
        };
        assert_eq!(p1.encode(&mut buf).unwrap(), "j9T");

        // p != 1
        let p2 = Params {
            flags: Flags::default(),
            n: 4096,
            r: 8,
            p: 4,
            t: 0,
            g: 0,
            nrom: 0,
        };
        assert_eq!(p2.encode(&mut buf).unwrap(), "j95.0");

        // t and g set
        let p3 = Params {
            flags: Flags::default(),
            n: 4096,
            r: 8,
            p: 1,
            t: 2,
            g: 5,
            nrom: 0,
        };
        assert_eq!(p3.encode(&mut buf).unwrap(), "j953/2");

        // NROM set (power of two)
        let p4 = Params {
            flags: Flags::default(),
            n: 32768,
            r: 8,
            p: 1,
            t: 0,
            g: 0,
            nrom: 4096,
        };
        assert_eq!(p4.encode(&mut buf).unwrap(), "jC559");
    }
}
