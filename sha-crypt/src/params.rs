//! Algorithm parameters.

use crate::errors;
use core::{
    default::Default,
    fmt::{self, Display},
    str::FromStr,
};

/// Default number of rounds.
pub const ROUNDS_DEFAULT: u32 = 5_000;

/// Minimum number of rounds allowed.
pub const ROUNDS_MIN: u32 = 1_000;

/// Maximum number of rounds allowed.
pub const ROUNDS_MAX: u32 = 999_999_999;

/// Algorithm parameters.
#[derive(Debug, Clone)]
pub struct Sha512Params {
    pub(crate) rounds: u32,
}

impl Default for Sha512Params {
    fn default() -> Self {
        Sha512Params {
            rounds: ROUNDS_DEFAULT,
        }
    }
}

impl Display for Sha512Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rounds={}", self.rounds)
    }
}

impl FromStr for Sha512Params {
    type Err = errors::Error;

    fn from_str(_s: &str) -> Result<Self, errors::Error> {
        todo!()
    }
}

impl Sha512Params {
    /// Create new algorithm parameters.
    pub fn new(rounds: u32) -> Result<Sha512Params, errors::Error> {
        if (ROUNDS_MIN..=ROUNDS_MAX).contains(&rounds) {
            Ok(Sha512Params { rounds })
        } else {
            Err(errors::Error::RoundsError)
        }
    }
}

/// Algorithm parameters.
#[derive(Debug, Clone)]
pub struct Sha256Params {
    pub(crate) rounds: u32,
}

impl Default for Sha256Params {
    fn default() -> Self {
        Sha256Params {
            rounds: ROUNDS_DEFAULT,
        }
    }
}

impl Display for Sha256Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rounds={}", self.rounds)
    }
}

impl FromStr for Sha256Params {
    type Err = errors::Error;

    fn from_str(_s: &str) -> Result<Self, errors::Error> {
        todo!()
    }
}

impl Sha256Params {
    /// Create new algorithm parameters.
    pub fn new(rounds: u32) -> Result<Sha256Params, errors::Error> {
        if (ROUNDS_MIN..=ROUNDS_MAX).contains(&rounds) {
            Ok(Sha256Params { rounds })
        } else {
            Err(errors::Error::RoundsError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ROUNDS_MAX, ROUNDS_MIN, Sha256Params, Sha512Params};

    #[test]
    fn test_sha256_crypt_invalid_rounds() {
        let params = Sha256Params::new(ROUNDS_MAX + 1);
        assert!(params.is_err());

        let params = Sha256Params::new(ROUNDS_MIN - 1);
        assert!(params.is_err());
    }

    #[test]
    fn test_sha512_crypt_invalid_rounds() {
        let params = Sha512Params::new(ROUNDS_MAX + 1);
        assert!(params.is_err());

        let params = Sha512Params::new(ROUNDS_MIN - 1);
        assert!(params.is_err());
    }
}
