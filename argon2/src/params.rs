//! Argon2 password hash parameters.

use crate::{Argon2, Version};
use core::convert::{TryFrom, TryInto};
use password_hash::{Decimal, ParamsString, PasswordHash};

/// Argon2 password hash parameters.
///
/// These are parameters which can be encoded into a PHC hash string.
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Params {
    /// Memory size, expressed in kilobytes, between 1 and (2^32)-1.
    ///
    /// Value is an integer in decimal (1 to 10 digits).
    pub m_cost: Decimal,

    /// Number of iterations, between 1 and (2^32)-1.
    ///
    /// Value is an integer in decimal (1 to 10 digits).
    pub t_cost: Decimal,

    /// Degree of parallelism, between 1 and 255.
    ///
    /// Value is an integer in decimal (1 to 3 digits).
    pub p_cost: Decimal,

    /// Size of the output (in bytes)
    pub output_size: usize,

    /// Algorithm version
    pub version: Version,
}

impl Default for Params {
    fn default() -> Params {
        let ctx = Argon2::default();

        Params {
            m_cost: ctx.m_cost,
            t_cost: ctx.t_cost,
            p_cost: ctx.threads,
            output_size: 32,
            version: Version::default(),
        }
    }
}

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
