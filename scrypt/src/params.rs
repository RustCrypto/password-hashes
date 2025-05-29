use core::mem::size_of;

use crate::errors::InvalidParams;

#[cfg(feature = "simple")]
use password_hash::{Error, ParamsString, PasswordHash, errors::InvalidValue};

#[cfg(doc)]
use password_hash::PasswordHasher;

/// The Scrypt parameter values.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Params {
    pub(crate) log_n: u8,
    pub(crate) r: u32,
    pub(crate) p: u32,
    #[cfg(feature = "password-hash")]
    pub(crate) len: Option<usize>,
}

impl Params {
    /// Recommended log₂ of the Scrypt parameter `N`: CPU/memory cost.
    pub const RECOMMENDED_LOG_N: u8 = 17;

    /// Recommended Scrypt parameter `r`: block size.
    pub const RECOMMENDED_R: u32 = 8;

    /// Recommended Scrypt parameter `p`: parallelism.
    pub const RECOMMENDED_P: u32 = 1;

    /// Recommended Scrypt parameter `Key length`.
    pub const RECOMMENDED_LEN: usize = 32;

    /// Create a new instance of [`Params`].
    ///
    /// # Arguments
    /// - `log_n` - The log₂ of the Scrypt parameter `N`
    /// - `r` - The Scrypt parameter `r`
    /// - `p` - The Scrypt parameter `p`
    ///
    /// # Conditions
    /// - `log_n` must be less than `64`
    /// - `r` must be greater than `0` and less than or equal to `4294967295`
    /// - `p` must be greater than `0` and less than `4294967295`
    pub fn new(log_n: u8, r: u32, p: u32) -> Result<Params, InvalidParams> {
        let cond1 = (log_n as usize) < usize::BITS as usize;
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
            #[cfg(feature = "password-hash")]
            len: None,
        })
    }

    /// Create a new instance of [`Params`], overriding the output length.
    ///
    /// Note that this length is only intended for use with the [`PasswordHasher`] API, and not with
    /// the low-level [`scrypt::scrypt`][`crate::scrypt`] API, which determines the output length
    /// using the size of the `output` slice.
    ///
    /// The allowed values for `len` are between 10 bytes (80 bits) and 64 bytes inclusive.
    /// These lengths come from the [PHC string format specification](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md)
    /// because they are intended for use with password hash strings.
    #[cfg(feature = "password-hash")]
    pub fn new_with_output_len(
        log_n: u8,
        r: u32,
        p: u32,
        len: usize,
    ) -> Result<Params, InvalidParams> {
        if !(password_hash::Output::MIN_LENGTH..=password_hash::Output::MAX_LENGTH).contains(&len) {
            return Err(InvalidParams);
        }

        let mut ret = Self::new(log_n, r, p)?;
        ret.len = Some(len);
        Ok(ret)
    }

    /// Recommended values according to the [OWASP cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt)
    /// - `log_n = 17` (`n = 131072`)
    /// - `r = 8`
    /// - `p = 1`
    pub const fn recommended() -> Params {
        Params {
            log_n: Self::RECOMMENDED_LOG_N,
            r: Self::RECOMMENDED_R,
            p: Self::RECOMMENDED_P,
            #[cfg(feature = "password-hash")]
            len: None,
        }
    }

    /// log₂ of the Scrypt parameter `N`, the work factor.
    ///
    /// Memory and CPU usage scale linearly with `N`. If you need `N`, use
    /// [`Params::n`] instead.
    pub const fn log_n(&self) -> u8 {
        self.log_n
    }

    /// `N` parameter: the work factor.
    ///
    /// This method returns 2 to the power of [`Params::log_n`]. Memory and CPU
    /// usage scale linearly with `N`.
    pub const fn n(&self) -> u64 {
        1 << self.log_n
    }

    /// `r` parameter: resource usage.
    ///
    /// scrypt iterates 2*r times. Memory and CPU time scale linearly
    /// with this parameter.
    pub const fn r(&self) -> u32 {
        self.r
    }

    /// `p` parameter: parallelization.
    pub const fn p(&self) -> u32 {
        self.p
    }
}

impl Default for Params {
    fn default() -> Params {
        Params::recommended()
    }
}

#[cfg(feature = "simple")]
impl<'a> TryFrom<&'a PasswordHash<'a>> for Params {
    type Error = password_hash::Error;

    fn try_from(hash: &'a PasswordHash<'a>) -> Result<Self, password_hash::Error> {
        let mut log_n = Self::RECOMMENDED_LOG_N;
        let mut r = Self::RECOMMENDED_R;
        let mut p = Self::RECOMMENDED_P;

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

        let len = hash
            .hash
            .map(|out| out.len())
            .unwrap_or(Self::RECOMMENDED_LEN);

        Params::new_with_output_len(log_n, r, p, len)
            .map_err(|_| InvalidValue::Malformed.param_error())
    }
}

#[cfg(feature = "simple")]
impl TryFrom<Params> for ParamsString {
    type Error = password_hash::Error;

    fn try_from(input: Params) -> Result<ParamsString, password_hash::Error> {
        let mut output = ParamsString::new();
        output.add_decimal("ln", input.log_n as u32)?;
        output.add_decimal("r", input.r)?;
        output.add_decimal("p", input.p)?;
        Ok(output)
    }
}
