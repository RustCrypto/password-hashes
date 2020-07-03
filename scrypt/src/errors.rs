use core::fmt;

/// `scrypt()` error
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct InvalidOutputLen;

/// `ScryptParams` error
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct InvalidParams;

impl fmt::Display for InvalidOutputLen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid output buffer length")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidOutputLen {}

impl fmt::Display for InvalidParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid scrypt parameters")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidParams {}

/// `scrypt_check` error
#[cfg(feature = "include_simple")]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CheckError {
    /// Password hash mismatch, e.g. due to the incorrect password.
    HashMismatch,
    /// Invalid format of the hash string.
    InvalidFormat,
}

#[cfg(feature = "include_simple")]
impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            CheckError::HashMismatch => "password hash mismatch",
            CheckError::InvalidFormat => "invalid `hashed_value` format",
        })
    }
}

#[cfg(feature = "include_simple")]
impl From<base64::DecodeError> for CheckError {
    fn from(_e: ::base64::DecodeError) -> Self {
        CheckError::InvalidFormat
    }
}

#[cfg(all(feature = "include_simple", feature = "std"))]
impl std::error::Error for CheckError {}
