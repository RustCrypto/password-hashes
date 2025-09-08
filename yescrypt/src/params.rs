//! Algorithm parameters.

use crate::{
    Error, Flags, Result,
    encoding::{decode64_uint32, encode64_uint32},
    pwxform::{PwxformCtx, RMIN},
};
use core::{
    fmt::{self, Display},
    str::{self, FromStr},
};

/// `yescrypt` algorithm parameters.
///
/// These are various algorithm settings which can control e.g. the amount of resource utilization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Params {
    /// Flags which provide fine-grained behavior control.
    pub(crate) flags: Flags,

    /// `N`: CPU/memory cost (like `scrypt`).
    pub(crate) n: u64,

    /// `r`: block size (like `scrypt`).
    pub(crate) r: u32,

    /// `p`: parallelism (like `scrypt`).
    pub(crate) p: u32,

    /// special to yescrypt.
    pub(crate) t: u32,

    /// special to yescrypt.
    pub(crate) g: u32,

    /// special to yescrypt.
    pub(crate) nrom: u64,
}

impl Params {
    /// Maximum length of params when encoded as Base64: up to 8 params of up to 6 chars each.
    pub(crate) const MAX_ENCODED_LEN: usize = 8 * 6;

    /// Initialize params.
    pub fn new(flags: Flags, n: u64, r: u32, p: u32) -> Result<Params> {
        Self::new_with_all_params(flags, n, r, p, 0, 0)
    }

    /// Initialize params.
    pub fn new_with_all_params(
        flags: Flags,
        n: u64,
        r: u32,
        p: u32,
        t: u32,
        g: u32,
    ) -> Result<Params> {
        // TODO(tarcieri): support non-zero `g`?
        if g != 0 {
            return Err(Error::Params);
        }

        match flags & Flags::MODE_MASK {
            // 0 (masking and bitflags play somewhat oddly together)
            Flags::ROUNDS_3 => {
                // classic scrypt - can't have anything non-standard
                if !flags.is_empty() || t != 0 {
                    return Err(Error::Params);
                }
            }
            Flags::WORM => {
                if flags != Flags::WORM {
                    return Err(Error::Params);
                }
            }
            Flags::RW => {
                // TODO(tarcieri): are these checks redundant since we have well-typed flags?
                if flags != flags & (Flags::MODE_MASK | Flags::RW_FLAVOR_MASK | Flags::PREHASH) {
                    return Err(Error::Params);
                }

                if (flags & Flags::RW_FLAVOR_MASK)
                    != (Flags::ROUNDS_6 | Flags::GATHER_4 | Flags::SIMPLE_2 | Flags::SBOX_12K)
                {
                    return Err(Error::Params);
                }
            }
            _ => {
                return Err(Error::Params);
            }
        }

        if flags.contains(Flags::RW)
            && (n / (p as u64) <= 1
                || r < RMIN as u32
                || p as u64 > u64::MAX / (3 * (1 << 8) * 2 * 8)
                || p as u64 > u64::MAX / (size_of::<PwxformCtx<'_>>() as u64))
        {
            return Err(Error::Params);
        }

        Ok(Params {
            flags,
            n,
            r,
            p,
            t,
            g,
            nrom: 0,
        })
    }

    /// `N`: CPU/memory cost (like `scrypt`).
    ///
    /// Memory and CPU usage scale linearly with `N`.
    pub const fn n(&self) -> u64 {
        self.n
    }

    /// `r` parameter: resource usage (like `scrypt`).
    ///
    /// Memory and CPU usage scales linearly with this parameter.
    pub const fn r(&self) -> u32 {
        self.r
    }

    /// `p` parameter: parallelization (like `scrypt`).
    pub const fn p(&self) -> u32 {
        self.p
    }

    /// Encode params as (s)crypt-flavored Base64.
    #[allow(non_snake_case)]
    pub(crate) fn encode<'o>(&self, out: &'o mut [u8]) -> Result<&'o str> {
        let flavor = if self.flags.bits() < Flags::RW.bits() {
            self.flags.bits()
        } else if (self.flags & Flags::MODE_MASK) == Flags::RW
            && self.flags.bits() <= (Flags::RW | Flags::RW_FLAVOR_MASK).bits()
        {
            Flags::RW.bits() + (self.flags.bits() >> 2)
        } else {
            return Err(Error::Params);
        };

        let N_log2 = N2log2(self.n);
        if N_log2 == 0 {
            return Err(Error::Params);
        }

        let NROM_log2 = N2log2(self.nrom);
        if self.nrom != 0 && NROM_log2 == 0 {
            return Err(Error::Params);
        }

        if (self.r as u64) * (self.p as u64) >= (1 << 30) {
            return Err(Error::Params);
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

        // "have" bits signal which additional optional fields are present
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

        str::from_utf8(&out[..pos]).map_err(|_| Error::Encoding)
    }
}

impl Default for Params {
    // From the upstream C reference implementation's `PARAMETERS` file:
    //
    // > Large and slow (memory usage 16 MiB, performance like bcrypt cost 2^8 -
    // > latency 10-30 ms and throughput 1000+ per second on a 16-core server)
    fn default() -> Self {
        // flags = YESCRYPT_DEFAULTS, N = 4096, r = 32, p = 1, t = 0, g = 0, NROM = 0
        Params {
            flags: Flags::default(),
            n: 4096,
            r: 32,
            p: 1,
            t: 0,
            g: 0,
            nrom: 0,
        }
    }
}

impl FromStr for Params {
    type Err = Error;

    #[allow(non_snake_case)]
    fn from_str(s: &str) -> Result<Params> {
        let bytes = s.as_bytes();
        let mut pos = 0usize;

        // flags
        let (flavor, new_pos) = decode64_uint32(bytes, pos, 0)?;
        pos = new_pos;

        let flags = if flavor < Flags::RW.bits() {
            Flags::from_bits(flavor)
        } else if flavor <= Flags::RW.bits() + (Flags::RW_FLAVOR_MASK.bits() >> 2) {
            Flags::from_bits(Flags::RW.bits() + ((flavor - Flags::RW.bits()) << 2))
        } else {
            return Err(Error::Params);
        }
        .ok_or(Error::Encoding)?;

        // Nlog2
        let (nlog2, new_pos) = decode64_uint32(bytes, pos, 1)?;
        pos = new_pos;
        if nlog2 > 63 {
            return Err(Error::Encoding);
        }
        let n = 1 << nlog2;

        // r
        let (r, new_pos) = decode64_uint32(bytes, pos, 1)?;
        pos = new_pos;

        let mut p = 1;
        let mut t = 0;
        let mut g = 0;

        if pos < bytes.len() {
            // "have" bits signaling which optional fields are present
            let (have, new_pos) = decode64_uint32(bytes, pos, 1)?;
            pos = new_pos;

            // p
            if (have & 0x01) != 0 {
                let (_p, new_pos) = decode64_uint32(bytes, pos, 2)?;
                pos = new_pos;
                p = _p;
            }

            // t
            if (have & 0x02) != 0 {
                let (_t, new_pos) = decode64_uint32(bytes, pos, 1)?;
                pos = new_pos;
                t = _t;
            }

            // g
            if (have & 0x04) != 0 {
                let (_g, new_pos) = decode64_uint32(bytes, pos, 1)?;
                pos = new_pos;
                g = _g;
            }

            // NROM
            if (have & 0x08) != 0 {
                let (nrom_log2, _) = decode64_uint32(bytes, pos, 1)?;
                if nrom_log2 != 0 {
                    return Err(Error::Params);
                }
            }
        }

        Self::new_with_all_params(flags, n, r, p, t, g)
    }
}

impl Display for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; Self::MAX_ENCODED_LEN];
        f.write_str(self.encode(&mut buf).expect("params encode failed"))
    }
}

#[allow(non_snake_case)]
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
    use alloc::string::ToString;

    #[test]
    fn encoder() {
        let p1 = Params {
            flags: Flags::default(),
            n: 4096,
            r: 32,
            p: 1,
            t: 0,
            g: 0,
            nrom: 0,
        };
        assert_eq!(p1.to_string(), "j9T");

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
        assert_eq!(p2.to_string(), "j95.0");

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
        assert_eq!(p3.to_string(), "j953/2");

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
        assert_eq!(p4.to_string(), "jC559");
    }

    #[test]
    fn decoder() {
        let p1: Params = "j9T".parse().unwrap();
        assert_eq!(
            p1,
            Params {
                flags: Flags::default(),
                n: 4096,
                r: 32,
                p: 1,
                t: 0,
                g: 0,
                nrom: 0,
            }
        );

        // p != 1
        let p2: Params = "j95.0".parse().unwrap();
        assert_eq!(
            p2,
            Params {
                flags: Flags::default(),
                n: 4096,
                r: 8,
                p: 4,
                t: 0,
                g: 0,
                nrom: 0,
            }
        );

        // g set
        // TODO(tarcieri): support non-zero g
        assert!("j953/2".parse::<Params>().is_err());

        // NROM set
        // TODO(tarcieri): support NROM
        assert!("jC559".parse::<Params>().is_err());
    }
}
