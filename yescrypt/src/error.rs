//! Error type.

use core::{fmt, num::TryFromIntError};

/// Result type for the `yescrypt` crate with its [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Invalid password hashing algorithm.
    #[cfg(feature = "simple")]
    Algorithm,

    /// Encoding error (i.e. Base64)
    Encoding,

    /// Internal error (bug in library)
    Internal,

    /// Invalid params
    Params,

    /// Invalid password
    #[cfg(feature = "simple")]
    Password,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "simple")]
            Error::Algorithm => write!(f, "password hash must begin with `$y$`"),
            Error::Encoding => write!(f, "yescrypt encoding invalid"),
            Error::Internal => write!(f, "internal error"),
            Error::Params => write!(f, "yescrypt params invalid"),
            #[cfg(feature = "simple")]
            Error::Password => write!(f, "invalid password"),
        }
    }
}

impl core::error::Error for Error {}

impl From<TryFromIntError> for Error {
    fn from(_: TryFromIntError) -> Self {
        Error::Internal
    }
}
