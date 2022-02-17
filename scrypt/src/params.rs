use core::mem::size_of;

use crate::errors::InvalidParams;

#[cfg(feature = "simple")]
use password_hash::{errors::InvalidValue, Error, ParamsString, PasswordHash};

const RECOMMENDED_LOG_N: u8 = 15;
const RECOMMENDED_R: u32 = 8;
const RECOMMENDED_P: u32 = 1;
const RECOMMENDED_LEN: usize = 32;

/// The Scrypt parameter values.
#[derive(Clone, Copy, Debug)]
pub struct Params {
    pub(crate) log_n: u8,
    pub(crate) r: u32,
    pub(crate) p: u32,
    #[allow(dead_code)] // this field is used only with the `PasswordHasher` impl
    pub(crate) len: usize,
}

impl Params {
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
    pub fn new(log_n: u8, r: u32, p: u32) -> Result<Params, InvalidParams> {
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

        Ok(Params {
            log_n,
            r: r as u32,
            p: p as u32,
            len: RECOMMENDED_LEN,
        })
    }

    /// Recommended values sufficient for most use-cases
    /// - `log_n = 15` (`n = 32768`)
    /// - `r = 8`
    /// - `p = 1`
    pub fn recommended() -> Params {
        Params {
            log_n: RECOMMENDED_LOG_N,
            r: RECOMMENDED_R,
            p: RECOMMENDED_P,
            len: RECOMMENDED_LEN,
        }
    }

    /// log2 of the Scrypt parameter `N`, the work factor.
    ///
    /// Memory and CPU usage scale linearly with `N`.
    pub fn log_n(&self) -> u8 {
        self.log_n
    }

    /// `r` parameter: resource usage.
    ///
    /// scrypt iterates 2*r times. Memory and CPU time scale linearly
    /// with this parameter.
    pub fn r(&self) -> u32 {
        self.r
    }

    /// `p` parameter: parallelization.
    pub fn p(&self) -> u32 {
        self.p
    }
}

impl Default for Params {
    fn default() -> Params {
        Params::recommended()
    }
}

#[cfg(feature = "simple")]
#[cfg_attr(docsrs, doc(cfg(feature = "simple")))]
impl<'a> TryFrom<&'a PasswordHash<'a>> for Params {
    type Error = password_hash::Error;

    fn try_from(hash: &'a PasswordHash<'a>) -> Result<Self, password_hash::Error> {
        let mut log_n = RECOMMENDED_LOG_N;
        let mut r = RECOMMENDED_R;
        let mut p = RECOMMENDED_P;

        if hash.version.is_some() {
            return Err(Error::Version);
        }

        for (ident, value) in hash.params.iter() {
            match ident.as_str() {
                "ln" => {
                    log_n = value
                        .decimal()?
                        .try_into()
                        .map_err(|_| InvalidValue::Malformed.param_error())?
                }
                "r" => r = value.decimal()?,
                "p" => p = value.decimal()?,
                _ => return Err(password_hash::Error::ParamNameInvalid),
            }
        }

        Params::new(log_n, r, p).map_err(|_| InvalidValue::Malformed.param_error())
    }
}

#[cfg(feature = "simple")]
#[cfg_attr(docsrs, doc(cfg(feature = "simple")))]
impl<'a> TryFrom<Params> for ParamsString {
    type Error = password_hash::Error;

    fn try_from(input: Params) -> Result<ParamsString, password_hash::Error> {
        let mut output = ParamsString::new();
        output.add_decimal("ln", input.log_n as u32)?;
        output.add_decimal("r", input.r)?;
        output.add_decimal("p", input.p)?;
        Ok(output)
    }
}
