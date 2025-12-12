//! Error types.

use core::fmt;

/// Result type for the `sha-crypt` crate with its [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Debug)]
pub enum Error {
    /// Should be within range defs::ROUNDS_MIN < defs::ROUNDS_MIN
    RoundsError,
}

impl core::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::RoundsError => write!(f, "rounds error"),
        }
    }
}

#[cfg(feature = "simple")]
impl From<Error> for password_hash::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::RoundsError => password_hash::Error::ParamInvalid { name: "rounds" },
        }
    }
}
