//! Algorithm parameters.

use crate::errors;
use core::default::Default;

/// Default number of rounds.
pub const ROUNDS_DEFAULT: usize = 5_000;

/// Minimum number of rounds allowed.
pub const ROUNDS_MIN: usize = 1_000;

/// Maximum number of rounds allowed.
pub const ROUNDS_MAX: usize = 999_999_999;

/// Algorithm parameters.
#[derive(Debug, Clone)]
pub struct Sha512Params {
    pub(crate) rounds: usize,
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
    pub fn new(rounds: usize) -> Result<Sha512Params, errors::CryptError> {
        if (ROUNDS_MIN..=ROUNDS_MAX).contains(&rounds) {
            Ok(Sha512Params { rounds })
        } else {
            Err(errors::CryptError::RoundsError)
        }
    }
}
