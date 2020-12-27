use crate::errors;
use std::default::Default;
pub const ROUNDS_DEFAULT: usize = 5_000;
pub const ROUNDS_MIN: usize = 1_000;
pub const ROUNDS_MAX: usize = 999_999_999;

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
    pub fn new(rounds: usize) -> Result<Sha512Params, errors::CryptError> {
        if rounds < ROUNDS_MIN || rounds > ROUNDS_MAX {
            return Err(errors::CryptError::RoundsError);
        }
        Ok(Sha512Params { rounds })
    }
}
