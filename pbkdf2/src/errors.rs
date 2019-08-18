#![cfg(feature = "include_simple")]
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// `pbkdf2_check` error
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CheckError {
    /// Password hash mismatch, e.g. due to the incorrect password.
    HashMismatch,
    /// Invalid format of the hash string.
    InvalidFormat,
}

impl Display for CheckError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(self.description())
    }
}

impl Error for CheckError {
    fn description(&self) -> &str {
        match *self {
            CheckError::HashMismatch => "password hash mismatch",
            CheckError::InvalidFormat => "invalid `hashed_value` format",
        }
    }
}

impl From<base64::DecodeError> for CheckError {
    fn from(_e: base64::DecodeError) -> Self {
        CheckError::InvalidFormat
    }
}
