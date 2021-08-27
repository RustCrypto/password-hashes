//! Argon2 password hash parameters.

use crate::{Error, Result, SYNC_POINTS};
use core::convert::TryFrom;

#[cfg(feature = "password-hash")]
use {
    core::convert::TryInto,
    password_hash::{ParamsString, PasswordHash},
};

/// Argon2 password hash parameters.
///
/// These are parameters which can be encoded into a PHC hash string.
// TODO(tarcieri): make members private, ensure `Params` is always valid?
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Params {
    /// Memory size, expressed in kilobytes, between 1 and (2^32)-1.
    ///
    /// Value is an integer in decimal (1 to 10 digits).
    m_cost: u32,

    /// Number of iterations, between 1 and (2^32)-1.
    ///
    /// Value is an integer in decimal (1 to 10 digits).
    t_cost: u32,

    /// Degree of parallelism, between 1 and 255.
    ///
    /// Value is an integer in decimal (1 to 3 digits).
    p_cost: u32,

    /// Size of the output (in bytes).
    output_len: Option<usize>,
}

impl Params {
    /// Default memory cost.
    pub const DEFAULT_M_COST: u32 = 4096;

    /// Minimum number of memory blocks.
    pub const MIN_M_COST: u32 = 2 * SYNC_POINTS; // 2 blocks per slice

    /// Maximum number of memory blocks.
    pub const MAX_M_COST: u32 = 0x0FFFFFFF;

    /// Default number of iterations (i.e. "time").
    pub const DEFAULT_T_COST: u32 = 3;

    /// Minimum number of passes.
    pub const MIN_T_COST: u32 = 1;

    /// Maximum number of passes.
    pub const MAX_T_COST: u32 = u32::MAX;

    /// Default degree of parallelism.
    pub const DEFAULT_P_COST: u32 = 1;

    /// Minimum and maximum number of threads (i.e. parallelism).
    pub const MIN_P_COST: u32 = 1;

    /// Minimum and maximum number of threads (i.e. parallelism).
    pub const MAX_P_COST: u32 = 0xFFFFFF;

    /// Default output length.
    pub const DEFAULT_OUTPUT_LENGTH: usize = 32;

    /// Minimum digest size in bytes.
    pub const MIN_OUTPUT_LENGTH: usize = 4;

    /// Maximum digest size in bytes.
    pub const MAX_OUTPUT_LENGTH: usize = 0xFFFFFFFF;

    /// Create new parameters.
    pub fn new(m_cost: u32, t_cost: u32, p_cost: u32, output_len: Option<usize>) -> Result<Self> {
        let mut builder = ParamsBuilder::new()
            .m_cost(m_cost)?
            .t_cost(t_cost)?
            .p_cost(p_cost)?;

        if let Some(len) = output_len {
            builder = builder.output_len(len)?;
        }

        builder.params()
    }

    /// Memory size, expressed in kilobytes, between 1 and (2^32)-1.
    ///
    /// Value is an integer in decimal (1 to 10 digits).
    pub fn m_cost(self) -> u32 {
        self.m_cost
    }

    /// Number of iterations, between 1 and (2^32)-1.
    ///
    /// Value is an integer in decimal (1 to 10 digits).
    pub fn t_cost(self) -> u32 {
        self.t_cost
    }

    /// Degree of parallelism, between 1 and 255.
    ///
    /// Value is an integer in decimal (1 to 3 digits).
    pub fn p_cost(self) -> u32 {
        self.p_cost
    }

    /// Length of the output (in bytes).
    pub fn output_len(self) -> Option<usize> {
        self.output_len
    }
}

impl Default for Params {
    fn default() -> Params {
        Params {
            m_cost: Self::DEFAULT_M_COST,
            t_cost: Self::DEFAULT_T_COST,
            p_cost: Self::DEFAULT_P_COST,
            output_len: None,
        }
    }
}

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl<'a> TryFrom<&'a PasswordHash<'a>> for Params {
    type Error = password_hash::Error;

    fn try_from(hash: &'a PasswordHash<'a>) -> password_hash::Result<Self> {
        let mut params = ParamsBuilder::new();

        for (ident, value) in hash.params.iter() {
            match ident.as_str() {
                "m" => params = params.m_cost(value.decimal()?)?,
                "t" => params = params.t_cost(value.decimal()?)?,
                "p" => params = params.p_cost(value.decimal()?)?,
                "keyid" => (), // Ignored; correct key must be given to `Argon2` context
                // TODO(tarcieri): `data` parameter
                _ => return Err(password_hash::Error::ParamNameInvalid),
            }
        }

        if let Some(output) = &hash.hash {
            params = params.output_len(output.len())?;
        }

        Ok(params.try_into()?)
    }
}

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl<'a> TryFrom<Params> for ParamsString {
    type Error = password_hash::Error;

    fn try_from(params: Params) -> password_hash::Result<ParamsString> {
        let mut output = ParamsString::new();
        output.add_decimal("m", params.m_cost)?;
        output.add_decimal("t", params.t_cost)?;
        output.add_decimal("p", params.p_cost)?;
        Ok(output)
    }
}

/// Builder for Argon2 [`Params`].
pub struct ParamsBuilder {
    /// Parameters being constructed
    params: Params,
}

impl ParamsBuilder {
    /// Create a new builder with the default parameters.
    pub fn new() -> Self {
        Self {
            params: Params::default(),
        }
    }

    /// Set memory size, expressed in kilobytes, between 1 and (2^32)-1.
    pub fn m_cost(mut self, m_cost: u32) -> Result<Self> {
        if m_cost < Params::MIN_M_COST {
            return Err(Error::MemoryTooLittle);
        }

        if m_cost > Params::MAX_M_COST {
            return Err(Error::MemoryTooMuch);
        }

        self.params.m_cost = m_cost;
        Ok(self)
    }

    /// Set number of iterations, between 1 and (2^32)-1.
    pub fn t_cost(mut self, t_cost: u32) -> Result<Self> {
        if t_cost < Params::MIN_T_COST {
            return Err(Error::TimeTooSmall);
        }

        // Note: we don't need to check `MAX_T_COST`, since it's `u32::MAX`

        self.params.t_cost = t_cost;
        Ok(self)
    }

    /// Set degree of parallelism, between 1 and 255.
    pub fn p_cost(mut self, p_cost: u32) -> Result<Self> {
        if p_cost < Params::MIN_P_COST {
            return Err(Error::ThreadsTooFew);
        }

        if p_cost > Params::MAX_P_COST {
            return Err(Error::ThreadsTooMany);
        }

        self.params.p_cost = p_cost;
        Ok(self)
    }

    /// Set length of the output (in bytes).
    pub fn output_len(mut self, len: usize) -> Result<Self> {
        if len < Params::MIN_OUTPUT_LENGTH {
            return Err(Error::OutputTooShort);
        }

        if len > Params::MAX_OUTPUT_LENGTH {
            return Err(Error::OutputTooLong);
        }

        self.params.output_len = Some(len);
        Ok(self)
    }

    /// Get the finished [`Params`].
    ///
    /// This performs further validations to ensure that the given parameters
    /// are compatible with each other, and will return an error if they are not.
    ///
    /// The main validation is that `m_cost` < `p_cost * 8`
    pub fn params(self) -> Result<Params> {
        if self.params.m_cost < self.params.p_cost * 8 {
            return Err(Error::MemoryTooLittle);
        }

        Ok(self.params)
    }
}

impl Default for ParamsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TryFrom<ParamsBuilder> for Params {
    type Error = Error;

    fn try_from(builder: ParamsBuilder) -> Result<Params> {
        builder.params()
    }
}
