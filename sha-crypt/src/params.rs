//! Algorithm parameters.

use crate::{Error, Result};
use core::{
    default::Default,
    fmt::{self, Display},
    str::FromStr,
};

/// Algorithm parameters.
#[derive(Debug, Clone)]
pub struct Params {
    /// Number of times to apply the digest function
    pub(crate) rounds: u32,
}

impl Params {
    /// Default number of rounds.
    pub const ROUNDS_DEFAULT: u32 = 5_000;

    /// Minimum number of rounds allowed.
    pub const ROUNDS_MIN: u32 = 1_000;

    /// Maximum number of rounds allowed.
    pub const ROUNDS_MAX: u32 = 999_999_999;

    /// Create new algorithm parameters.
    pub fn new(rounds: u32) -> Result<Params> {
        match rounds {
            Self::ROUNDS_MIN..=Self::ROUNDS_MAX => Ok(Params { rounds }),
            _ => Err(Error::RoundsError),
        }
    }
}

impl Default for Params {
    fn default() -> Self {
        Params {
            rounds: Self::ROUNDS_DEFAULT,
        }
    }
}

impl Display for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rounds={}", self.rounds)
    }
}

impl FromStr for Params {
    type Err = Error;

    fn from_str(_s: &str) -> Result<Self> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::Params;

    #[test]
    fn test_sha256_crypt_invalid_rounds() {
        let params = Params::new(Params::ROUNDS_MAX + 1);
        assert!(params.is_err());

        let params = Params::new(Params::ROUNDS_MIN - 1);
        assert!(params.is_err());
    }

    #[test]
    fn test_sha512_crypt_invalid_rounds() {
        let params = Params::new(Params::ROUNDS_MAX + 1);
        assert!(params.is_err());

        let params = Params::new(Params::ROUNDS_MIN - 1);
        assert!(params.is_err());
    }
}
