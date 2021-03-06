//! Argon2 password hash parameters.

use crate::Version;

#[cfg(feature = "password-hash")]
use {
    core::convert::{TryFrom, TryInto},
    password_hash::{ParamsString, PasswordHash},
};

/// Argon2 password hash parameters.
///
/// These are parameters which can be encoded into a PHC hash string.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Params {
    /// Memory size, expressed in kilobytes, between 1 and (2^32)-1.
    ///
    /// Value is an integer in decimal (1 to 10 digits).
    pub m_cost: u32,

    /// Number of iterations, between 1 and (2^32)-1.
    ///
    /// Value is an integer in decimal (1 to 10 digits).
    pub t_cost: u32,

    /// Degree of parallelism, between 1 and 255.
    ///
    /// Value is an integer in decimal (1 to 3 digits).
    pub p_cost: u32,

    /// Size of the output (in bytes)
    pub output_size: usize,

    /// Algorithm version
    // TODO(tarcieri): make this separate from params in the next breaking release?
    pub version: Version,
}

impl Params {
    /// Default memory cost.
    pub const DEFAULT_M_COST: u32 = 4096;

    /// Default number of iterations.
    pub const DEFAULT_T_COST: u32 = 3;

    /// Default degree of parallelism.
    pub const DEFAULT_P_COST: u32 = 1;

    /// Default output size.
    pub const DEFAULT_OUTPUT_SIZE: usize = 32;
}

impl Default for Params {
    fn default() -> Params {
        Params {
            m_cost: Self::DEFAULT_M_COST,
            t_cost: Self::DEFAULT_T_COST,
            p_cost: Self::DEFAULT_P_COST,
            output_size: Self::DEFAULT_OUTPUT_SIZE,
            version: Version::default(),
        }
    }
}

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl<'a> TryFrom<&'a PasswordHash<'a>> for Params {
    type Error = password_hash::Error;

    fn try_from(hash: &'a PasswordHash<'a>) -> Result<Self, password_hash::Error> {
        let mut params = Params::default();

        for (ident, value) in hash.params.iter() {
            match ident.as_str() {
                "m" => params.m_cost = value.decimal()?,
                "t" => params.t_cost = value.decimal()?,
                "p" => params.p_cost = value.decimal()?,
                "keyid" => (), // Ignored; correct key must be given to `Argon2` context
                // TODO(tarcieri): `data` parameter
                _ => return Err(password_hash::Error::ParamNameInvalid),
            }
        }

        if let Some(version) = hash.version {
            params.version = version
                .try_into()
                .map_err(|_| password_hash::Error::Version)?;
        }

        if let Some(output) = &hash.hash {
            params.output_size = output.len();
        }

        Ok(params)
    }
}

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl<'a> TryFrom<Params> for ParamsString {
    type Error = password_hash::Error;

    fn try_from(params: Params) -> Result<ParamsString, password_hash::Error> {
        let mut output = ParamsString::new();
        output.add_decimal("m", params.m_cost)?;
        output.add_decimal("t", params.t_cost)?;
        output.add_decimal("p", params.p_cost)?;
        Ok(output)
    }
}
