//! Error type.

use core::{fmt, num::TryFromIntError};

/// Result type for the `yescrypt` crate with its [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Encoding error (i.e. Base64)
    Encoding,

    /// Internal error (bug in library)
    Internal,

    /// Invalid params
    Params,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Encoding => write!(f, "yescrypt encoding invalid"),
            Error::Internal => write!(f, "internal error"),
            Error::Params => write!(f, "yescrypt params invalid"),
        }
    }
}

impl core::error::Error for Error {}

impl From<TryFromIntError> for Error {
    fn from(_: TryFromIntError) -> Self {
        Error::Internal
    }
}

#[cfg(feature = "kdf")]
impl From<Error> for kdf::Error {
    fn from(_: Error) -> Self {
        kdf::Error
    }
}

#[cfg(feature = "password-hash")]
impl From<Error> for password_hash::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::Encoding => password_hash::Error::EncodingInvalid,
            Error::Internal => password_hash::Error::Internal,
            Error::Params => password_hash::Error::ParamsInvalid,
        }
    }
}
