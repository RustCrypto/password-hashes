//! Balloon password hash parameters.

use crate::{Error, Result};
use core::num::NonZeroU32;
#[cfg(feature = "password-hash")]
use {
    core::convert::TryFrom,
    password_hash::{errors::InvalidValue, ParamsString, PasswordHash},
};

/// Balloon password hash parameters.
///
/// These are parameters which can be encoded into a PHC hash string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Params {
    /// Space cost, expressed in of blocks.
    pub s_cost: NonZeroU32,
    /// Time cost, expressed in number of rounds.
    pub t_cost: NonZeroU32,
    /// Degree of parallelism, expressed in number of threads.
    /// Only allowed to be higher than 1 when used in combination
    /// with [`Algorithm::BalloonM`](crate::Algorithm::BalloonM).
    pub p_cost: NonZeroU32,
}

impl Params {
    /// Default memory cost.
    pub const DEFAULT_S_COST: u32 = 1024;

    /// Default number of iterations (i.e. "time").
    pub const DEFAULT_T_COST: u32 = 3;

    /// Default degree of parallelism.
    pub const DEFAULT_P_COST: u32 = 1;

    /// Create new parameters.
    pub fn new(s_cost: u32, t_cost: u32, p_cost: u32) -> Result<Self> {
        Ok(Self {
            s_cost: NonZeroU32::new(s_cost).ok_or(Error::MemoryTooLittle)?,
            t_cost: NonZeroU32::new(t_cost).ok_or(Error::TimeTooSmall)?,
            p_cost: NonZeroU32::new(p_cost).ok_or(Error::ThreadsTooFew)?,
        })
    }
}

impl Default for Params {
    fn default() -> Self {
        Self::new(
            Self::DEFAULT_S_COST,
            Self::DEFAULT_T_COST,
            Self::DEFAULT_P_COST,
        )
        .unwrap()
    }
}

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl<'a> TryFrom<&'a PasswordHash<'a>> for Params {
    type Error = password_hash::Error;

    fn try_from(hash: &'a PasswordHash<'a>) -> password_hash::Result<Self> {
        let mut params = Self::default();

        for (ident, value) in hash.params.iter() {
            match ident.as_str() {
                "s" => {
                    params.s_cost = NonZeroU32::new(value.decimal()?)
                        .ok_or_else(|| InvalidValue::TooShort.param_error())?;
                }
                "t" => {
                    params.t_cost = NonZeroU32::new(value.decimal()?)
                        .ok_or_else(|| InvalidValue::TooShort.param_error())?;
                }
                "p" => {
                    params.p_cost = NonZeroU32::new(value.decimal()?)
                        .ok_or_else(|| InvalidValue::TooShort.param_error())?;
                }
                _ => return Err(password_hash::Error::ParamNameInvalid),
            }
        }

        Ok(params)
    }
}

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl<'a> TryFrom<Params> for ParamsString {
    type Error = password_hash::Error;

    fn try_from(params: Params) -> password_hash::Result<ParamsString> {
        ParamsString::try_from(&params)
    }
}

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl<'a> TryFrom<&Params> for ParamsString {
    type Error = password_hash::Error;

    fn try_from(params: &Params) -> password_hash::Result<ParamsString> {
        let mut output = ParamsString::new();
        output.add_decimal("s", params.s_cost.get())?;
        output.add_decimal("t", params.t_cost.get())?;
        output.add_decimal("p", params.p_cost.get())?;

        Ok(output)
    }
}
