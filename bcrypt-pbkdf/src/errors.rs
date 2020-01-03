use std::{error, fmt};

/// `bcrypt_pbkdf` error
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An input parameter has an invalid length.
    InvalidParamLen,
    /// An invalid number of rounds was specified.
    InvalidRounds,
    /// The output parameter has an invalid length.
    InvalidOutputLen,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidParamLen => write!(f, "Invalid parameter length"),
            Error::InvalidRounds => write!(f, "Invalid number of rounds"),
            Error::InvalidOutputLen => write!(f, "Invalid output length"),
        }
    }
}

impl error::Error for Error {}
