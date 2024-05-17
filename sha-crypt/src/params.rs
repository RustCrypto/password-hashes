//! Algorithm parameters.

use crate::errors;
use core::default::Default;

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

impl Sha512Params {
    /// Create new algorithm parameters.
    pub fn new(rounds: u32) -> Result<Sha512Params, errors::CryptError> {
        if (ROUNDS_MIN..=ROUNDS_MAX).contains(&rounds) {
            Ok(Sha512Params { rounds })
        } else {
            Err(errors::CryptError::RoundsError)
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

impl Sha256Params {
    /// Create new algorithm parameters.
    pub fn new(rounds: u32) -> Result<Sha256Params, errors::CryptError> {
        if (ROUNDS_MIN..=ROUNDS_MAX).contains(&rounds) {
            Ok(Sha256Params { rounds })
        } else {
            Err(errors::CryptError::RoundsError)
        }
    }
}
