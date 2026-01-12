use core::{
    fmt::{self, Display},
    str::FromStr,
};

#[cfg(feature = "phc")]
use password_hash::{
    Error, Result,
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
    /// Minimum supported output length.
    // Uses the same recommendation as the PHC spec.
    pub const MIN_OUTPUT_LENGTH: usize = 10;

    /// Maximum supported output length.
    pub const MAX_OUTPUT_LENGTH: usize = 64;

    /// Minimum supported number of rounds, adapted from NIST's suggestions.
    pub const MIN_ROUNDS: u32 = 1000;

    /// Recommended output length.
    pub const RECOMMENDED_OUTPUT_LENGTH: usize = 32;

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
        output_len: Self::RECOMMENDED_OUTPUT_LENGTH,
    };

    /// Create new params with the given number of rounds.
    pub const fn new(rounds: u32) -> Result<Self> {
        Self::new_with_output_len(rounds, Self::RECOMMENDED_OUTPUT_LENGTH)
    }

    /// Create new params with a customized output length.
    pub const fn new_with_output_len(rounds: u32, output_len: usize) -> Result<Self> {
        if rounds < Self::MIN_ROUNDS
            || output_len < Self::MIN_OUTPUT_LENGTH
            || output_len > Self::MAX_OUTPUT_LENGTH
        {
            return Err(Error::ParamsInvalid);
        }

        Ok(Self { rounds, output_len })
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
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        u32::from_str(s)
            .map_err(|_| Error::EncodingInvalid)
            .and_then(Params::new)
    }
}

impl TryFrom<u32> for Params {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        Self::new(value)
    }
}

#[cfg(feature = "phc")]
impl TryFrom<&ParamsString> for Params {
    type Error = Error;

    fn try_from(params_string: &ParamsString) -> password_hash::Result<Self> {
        let mut rounds = Params::RECOMMENDED_ROUNDS;
        let mut output_len = Params::RECOMMENDED_OUTPUT_LENGTH;

        for (ident, value) in params_string.iter() {
            match ident.as_str() {
                "i" => {
                    rounds = value
                        .decimal()
                        .map_err(|_| Error::ParamInvalid { name: "i" })?;

                    if rounds < Self::MIN_ROUNDS {
                        return Err(Error::ParamInvalid { name: "i" });
                    }
                }
                "l" => {
                    output_len = value
                        .decimal()
                        .ok()
                        .and_then(|dec| dec.try_into().ok())
                        .ok_or(Error::ParamInvalid { name: "l" })?;

                    if output_len > Self::MAX_OUTPUT_LENGTH {
                        return Err(Error::ParamInvalid { name: "l" });
                    }
                }
                _ => return Err(Error::ParamsInvalid),
            }
        }

        Params::new_with_output_len(rounds, output_len)
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
