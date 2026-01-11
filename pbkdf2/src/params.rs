use core::{
    fmt::{self, Display},
    num::ParseIntError,
    str::FromStr,
};

#[cfg(feature = "phc")]
use password_hash::{
    Error,
    phc::{self, Decimal, ParamsString},
};

/// PBKDF2 params
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Params {
    /// Number of rounds
    rounds: u32,

    /// Size of the output (in bytes)
    output_len: usize,
}

impl Params {
    /// Maximum supported output length.
    pub const MAX_LENGTH: usize = 64;

    /// Recommended output length.
    pub const RECOMMENDED_LENGTH: usize = 32;

    /// Recommended number of PBKDF2 rounds (used by default).
    ///
    /// This number is adopted from the [OWASP cheat sheet]:
    ///
    /// > Use PBKDF2 with a work factor of 600,000 or more
    ///
    /// [OWASP cheat sheet]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    pub const RECOMMENDED_ROUNDS: u32 = 600_000;

    /// Recommended PBKDF2 parameters adapted from the [OWASP cheat sheet].
    ///
    /// [OWASP cheat sheet]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    pub const RECOMMENDED: Self = Params {
        rounds: Self::RECOMMENDED_ROUNDS,
        output_len: Self::RECOMMENDED_LENGTH,
    };

    /// Create new params with the given number of rounds.
    pub const fn new(rounds: u32) -> Self {
        let mut ret = Self::RECOMMENDED;
        ret.rounds = rounds;
        ret
    }

    /// Create new params with a customized output length.
    pub const fn new_with_output_len(rounds: u32, output_length: usize) -> Self {
        Self {
            rounds,
            output_len: output_length,
        }
    }

    /// Get the number of rounds.
    pub const fn rounds(self) -> u32 {
        self.rounds
    }

    /// Get the output length.
    pub const fn output_len(self) -> usize {
        self.output_len
    }
}

impl Default for Params {
    fn default() -> Params {
        Params::RECOMMENDED
    }
}

impl Display for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.rounds)
    }
}

impl FromStr for Params {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, ParseIntError> {
        u32::from_str(s).map(Params::new)
    }
}

#[cfg(feature = "phc")]
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
                    let len = value
                        .decimal()
                        .ok()
                        .and_then(|dec| dec.try_into().ok())
                        .ok_or(Error::ParamInvalid { name: "l" })?;

                    if len > Self::MAX_LENGTH {
                        return Err(Error::ParamInvalid { name: "l" });
                    }

                    params.output_len = len;
                }
                _ => return Err(Error::ParamsInvalid),
            }
        }

        Ok(params)
    }
}

#[cfg(feature = "phc")]
impl TryFrom<&phc::PasswordHash> for Params {
    type Error = Error;

    fn try_from(hash: &phc::PasswordHash) -> password_hash::Result<Self> {
        if hash.version.is_some() {
            return Err(Error::Version);
        }

        let params = Self::try_from(&hash.params)?;

        if let Some(hash) = &hash.hash {
            if hash.len() != params.output_len {
                return Err(Error::OutputSize);
            }
        }

        Ok(params)
    }
}

#[cfg(feature = "phc")]
impl TryFrom<Params> for ParamsString {
    type Error = Error;

    fn try_from(params: Params) -> password_hash::Result<ParamsString> {
        Self::try_from(&params)
    }
}

#[cfg(feature = "phc")]
impl TryFrom<&Params> for ParamsString {
    type Error = Error;

    fn try_from(input: &Params) -> password_hash::Result<ParamsString> {
        let mut output = ParamsString::new();

        for (name, value) in [("i", input.rounds), ("l", input.output_len as Decimal)] {
            output
                .add_decimal(name, value)
                .map_err(|_| Error::ParamInvalid { name })?;
        }

        Ok(output)
    }
}
