use core::{mem::size_of, usize};

use crate::errors::InvalidParams;

/// The Scrypt parameter values.
#[derive(Clone, Copy)]
pub struct ScryptParams {
    pub(crate) log_n: u8,
    pub(crate) r: u32,
    pub(crate) p: u32,
}

impl ScryptParams {
    /// Create a new instance of ScryptParams.
    ///
    /// # Arguments
    /// - `log_n` - The log2 of the Scrypt parameter `N`
    /// - `r` - The Scrypt parameter `r`
    /// - `p` - The Scrypt parameter `p`
    /// # Conditions
    /// - `log_n` must be less than `64`
    /// - `r` must be greater than `0` and less than or equal to `4294967295`
    /// - `p` must be greater than `0` and less than `4294967295`
    pub fn new(log_n: u8, r: u32, p: u32) -> Result<ScryptParams, InvalidParams> {
        let cond1 = (log_n as usize) < size_of::<usize>() * 8;
        let cond2 = size_of::<usize>() >= size_of::<u32>();
        let cond3 = r <= usize::MAX as u32 && p < usize::MAX as u32;
        if !(r > 0 && p > 0 && cond1 && (cond2 || cond3)) {
            return Err(InvalidParams);
        }

        let r = r as usize;
        let p = p as usize;

        let n: usize = 1 << log_n;

        // check that r * 128 doesn't overflow
        let r128 = r.checked_mul(128).ok_or(InvalidParams)?;

        // check that n * r * 128 doesn't overflow
        r128.checked_mul(n).ok_or(InvalidParams)?;

        // check that p * r * 128 doesn't overflow
        r128.checked_mul(p).ok_or(InvalidParams)?;

        // This check required by Scrypt:
        // check: n < 2^(128 * r / 8)
        // r * 16 won't overflow since r128 didn't
        if (log_n as usize) >= r * 16 {
            return Err(InvalidParams);
        }

        // This check required by Scrypt:
        // check: p <= ((2^32-1) * 32) / (128 * r)
        // It takes a bit of re-arranging to get the check above into this form,
        // but it is indeed the same.
        if r * p >= 0x4000_0000 {
            return Err(InvalidParams);
        }

        Ok(ScryptParams {
            log_n,
            r: r as u32,
            p: p as u32,
        })
    }

    /// Recommended values sufficient for most use-cases
    /// - `log_n = 15` (`n = 32768`)
    /// - `r = 8`
    /// - `p = 1`
    pub fn recommended() -> ScryptParams {
        ScryptParams {
            log_n: 15,
            r: 8,
            p: 1,
        }
    }
}
