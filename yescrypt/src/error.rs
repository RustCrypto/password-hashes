//! Error type.

use core::fmt;

/// Error type.
#[derive(Debug)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "yescrypt error")
    }
}

impl core::error::Error for Error {}

/// Result type for the `yescrypt` crate.
pub type Result<T> = core::result::Result<T, Error>;
