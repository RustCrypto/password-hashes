//! Algorithm parameters.

use crate::{Error, Flags, Result, encoding::encode64_uint32};
use core::str;

/// `yescrypt` algorithm parameters.
///
/// These are various algorithm settings which can control e.g. the amount of resource utilization.
#[derive(Clone, Copy, Debug)]
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
    pub const MAX_ENCODED_LEN: usize = 8 * 6;

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
