//! Algorithm parameters.

use crate::{
    Error, Flags, Result,
    encoding::{decode64_uint32, encode64_uint32},
};
use alloc::string::{String, ToString};
use core::str::{self, FromStr};

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
    pub const fn new(flags: Flags, n: u64, r: u32, p: u32) -> Params {
        Self::new_with_all_params(flags, n, r, p, 0, 0)
    }

    /// Initialize params.
    pub const fn new_with_all_params(
        flags: Flags,
        n: u64,
        r: u32,
        p: u32,
        t: u32,
        g: u32,
    ) -> Params {
        Params {
            flags,
            n,
            r,
            p,
            t,
            g,
            nrom: 0,
        }
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

        str::from_utf8(&out[..pos]).map_err(|_| Error)
    }
}

impl Default for Params {
    // From the upstream C reference implementation's `PARAMETERS` file:
    //
    // > Large and slow (memory usage 16 MiB, performance like bcrypt cost 2^8 -
    // > latency 10-30 ms and throughput 1000+ per second on a 16-core server)
    fn default() -> Self {
        // flags = YESCRYPT_DEFAULTS, N = 4096, r = 32, p = 1, t = 0, g = 0, NROM = 0
        Params::new(Flags::default(), 4096, 32, 1)
    }
}

impl FromStr for Params {
    type Err = Error;

    #[allow(non_snake_case)]
    fn from_str(s: &str) -> Result<Params> {
        let bytes = s.as_bytes();
        let mut pos = 0usize;

        // flags
        let (flavor, new_pos) = decode64_uint32(bytes, pos, 0).ok_or(Error)?;
        pos = new_pos;

        let flags = if flavor < Flags::RW.bits() {
            Flags::from_bits(flavor)
        } else if flavor <= Flags::RW.bits() + (Flags::RW_FLAVOR_MASK.bits() >> 2) {
            Flags::from_bits(Flags::RW.bits() + ((flavor - Flags::RW.bits()) << 2))
        } else {
            return Err(Error);
        }
        .ok_or(Error)?;

        // Nlog2
        let (nlog2, new_pos) = decode64_uint32(bytes, pos, 1).ok_or(Error)?;
        pos = new_pos;
        if nlog2 > 63 {
            return Err(Error);
        }
        let n = 1 << nlog2;

        // r
        let (r, new_pos) = decode64_uint32(bytes, pos, 1).ok_or(Error)?;
        pos = new_pos;

        let mut params = Self {
            flags,
            n,
            r,
            p: 1,
            t: 0,
            g: 0,
            nrom: 0,
        };

        if pos < bytes.len() {
            // "have" bits signaling which optional fields are present
            let (have, new_pos) = decode64_uint32(bytes, pos, 1).ok_or(Error)?;
            pos = new_pos;

            // p
            if (have & 0x01) != 0 {
                let (p, new_pos) = decode64_uint32(bytes, pos, 2).ok_or(Error)?;
                pos = new_pos;
                params.p = p;
            }

            // t
            if (have & 0x02) != 0 {
                let (t, new_pos) = decode64_uint32(bytes, pos, 1).ok_or(Error)?;
                pos = new_pos;
                params.t = t;
            }

            // g
            if (have & 0x04) != 0 {
                let (g, new_pos) = decode64_uint32(bytes, pos, 1).ok_or(Error)?;
                pos = new_pos;
                params.g = g;
            }

            // NROM
            if (have & 0x08) != 0 {
                let (nrom_log2, _) = decode64_uint32(bytes, pos, 1).ok_or(Error)?;
                if nrom_log2 > 63 {
                    return Err(Error);
                }
                params.nrom = 1 << nrom_log2;
            }
        }

        Ok(params)
    }
}

impl ToString for Params {
    fn to_string(&self) -> String {
        let mut buf = [0u8; Self::MAX_ENCODED_LEN];
        self.encode(&mut buf).expect("params encode failed").into()
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

        // t and g set
        let p3: Params = "j953/2".parse().unwrap();
        assert_eq!(
            p3,
            Params {
                flags: Flags::default(),
                n: 4096,
                r: 8,
                p: 1,
                t: 2,
                g: 5,
                nrom: 0,
            }
        );

        // NROM set (power of two)
        let p4: Params = "jC559".parse().unwrap();
        assert_eq!(
            p4,
            Params {
                flags: Flags::default(),
                n: 32768,
                r: 8,
                p: 1,
                t: 0,
                g: 0,
                nrom: 4096,
            }
        );
    }
}
