//! Error types.

use core::fmt;

/// Result type for the `sha-crypt` crate with its [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Debug)]
pub enum Error {
    /// Parameters are invalid (e.g. parse error)
    ParamsInvalid,

    /// `rounds=` be within range [`Params::ROUNDS_MIN`]..=[`Params::ROUNDS_MIN`]
    RoundsInvalid,
}

impl core::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ParamsInvalid => write!(f, "parameters are invalid"),
            Error::RoundsInvalid => write!(f, "rounds error"),
        }
    }
}

#[cfg(feature = "simple")]
impl From<Error> for password_hash::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::RoundsInvalid => password_hash::Error::ParamInvalid { name: "rounds" },
            Error::ParamsInvalid => password_hash::Error::ParamsInvalid,
        }
    }
}
