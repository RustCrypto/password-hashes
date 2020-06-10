#![cfg(feature="include_simple")]
use core::fmt;

/// `pbkdf2_check` error
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CheckError {
    /// Password hash mismatch, e.g. due to the incorrect password.
    HashMismatch,
    /// Invalid format of the hash string.
    InvalidFormat,
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            CheckError::HashMismatch => "password hash mismatch",
            CheckError::InvalidFormat => "invalid `hashed_value` format",
        })
    }
}

impl From<base64::DecodeError> for CheckError {
    fn from(_e: ::base64::DecodeError) -> Self {
        CheckError::InvalidFormat
    }
}

#[cfg(featue = "std")]
impl std::error::Error for CheckError { }
