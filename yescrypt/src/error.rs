//! Error type.

use core::fmt;

/// Error type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Encoding error (i.e. Base64)
    Encoding,

    /// Invalid params
    Params,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Encoding => f.write_str("yescrypt encoding invalid"),
            Error::Params => f.write_str("yescrypt params invalid"),
        }
    }
}

impl core::error::Error for Error {}

/// Result type for the `yescrypt` crate with its [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;
