//! Error type.

use core::fmt;

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
            Error::Algorithm => f.write_str("password hash must begin with `$y$`"),
            Error::Encoding => f.write_str("yescrypt encoding invalid"),
            Error::Params => f.write_str("yescrypt params invalid"),
            #[cfg(feature = "simple")]
            Error::Password => f.write_str("invalid password"),
        }
    }
}

impl core::error::Error for Error {}
