//! Error type.

use core::fmt;

/// Error type.
#[derive(Debug)]
pub struct Error(pub(crate) i32);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "yescrypt error (code {})", self.0)
    }
}

impl core::error::Error for Error {}

/// Result type for the `yescrypt` crate.
pub type Result<T> = core::result::Result<T, Error>;
