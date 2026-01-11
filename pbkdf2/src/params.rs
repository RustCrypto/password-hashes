use core::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};
use password_hash::{
    Error,
    phc::{Decimal, ParamsString, PasswordHash},
};

/// PBKDF2 params
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Params {
    /// Number of rounds
    pub rounds: u32,

    /// Size of the output (in bytes)
    pub output_length: usize,
}

impl Params {
    /// Recommended number of PBKDF2 rounds (used by default).
    ///
    /// This number is adopted from the [OWASP cheat sheet]:
    ///
    /// > Use PBKDF2 with a work factor of 600,000 or more
    ///
    /// [OWASP cheat sheet]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    pub const RECOMMENDED_ROUNDS: usize = 600_000;

    /// Recommended PBKDF2 parameters adapted from the [OWASP cheat sheet].
    ///
    /// [OWASP cheat sheet]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    pub const RECOMMENDED: Self = Params {
        rounds: Self::RECOMMENDED_ROUNDS as u32,
        output_length: 32,
    };
}

impl Default for Params {
    fn default() -> Params {
        Params::RECOMMENDED
    }
}

impl Display for Params {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        ParamsString::try_from(self).map_err(|_| fmt::Error)?.fmt(f)
    }
}

impl FromStr for Params {
    type Err = Error;

    fn from_str(s: &str) -> password_hash::Result<Self> {
        let params_string = ParamsString::from_str(s).map_err(|_| Error::ParamsInvalid)?;
        Self::try_from(&params_string)
    }
}

impl TryFrom<&ParamsString> for Params {
    type Error = Error;

    fn try_from(params_string: &ParamsString) -> password_hash::Result<Self> {
        let mut params = Params::default();

        for (ident, value) in params_string.iter() {
            match ident.as_str() {
                "i" => {
                    params.rounds = value
                        .decimal()
                        .map_err(|_| Error::ParamInvalid { name: "i" })?
                }
                "l" => {
                    params.output_length = value
                        .decimal()
                        .ok()
                        .and_then(|dec| dec.try_into().ok())
                        .ok_or(Error::ParamInvalid { name: "l" })?;
                }
                _ => return Err(Error::ParamsInvalid),
            }
        }

        Ok(params)
    }
}

impl TryFrom<&PasswordHash> for Params {
    type Error = Error;

    fn try_from(hash: &PasswordHash) -> password_hash::Result<Self> {
        if hash.version.is_some() {
            return Err(Error::Version);
        }

        let params = Self::try_from(&hash.params)?;

        if let Some(hash) = &hash.hash {
            if hash.len() != params.output_length {
                return Err(Error::OutputSize);
            }
        }

        Ok(params)
    }
}

impl TryFrom<Params> for ParamsString {
    type Error = Error;

    fn try_from(params: Params) -> password_hash::Result<ParamsString> {
        Self::try_from(&params)
    }
}

impl TryFrom<&Params> for ParamsString {
    type Error = Error;

    fn try_from(input: &Params) -> password_hash::Result<ParamsString> {
        let mut output = ParamsString::new();

        for (name, value) in [("i", input.rounds), ("l", input.output_length as Decimal)] {
            output
                .add_decimal(name, value)
                .map_err(|_| Error::ParamInvalid { name })?;
        }

        Ok(output)
    }
}
