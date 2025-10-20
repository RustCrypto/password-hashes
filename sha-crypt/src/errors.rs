//! Error types.

use alloc::string;
use core::fmt;

#[cfg(feature = "simple")]
use alloc::string::String;

/// Error type.
#[derive(Debug)]
pub enum CryptError {
    /// Should be within range defs::ROUNDS_MIN < defs::ROUNDS_MIN
    RoundsError,

    /// RNG failed.
    RandomError,

    /// UTF-8 error.
    StringError(string::FromUtf8Error),
}

impl From<string::FromUtf8Error> for CryptError {
    fn from(e: string::FromUtf8Error) -> Self {
        CryptError::StringError(e)
    }
}

impl core::error::Error for CryptError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            CryptError::StringError(err) => Some(err),
            _ => None,
        }
    }
}

impl fmt::Display for CryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptError::RoundsError => write!(f, "rounds error"),
            CryptError::RandomError => write!(f, "random error"),
            CryptError::StringError(_) => write!(f, "string error"),
        }
    }
}

/// Errors which occur when verifying passwords.
#[cfg(feature = "simple")]
#[derive(Debug)]
pub enum CheckError {
    /// Format is invalid.
    InvalidFormat(String),

    /// Cryptographic error.
    Crypt(CryptError),

    /// Password hash doesn't match (invalid password).
    HashMismatch,
}

/// Decoding errors.
#[cfg(feature = "simple")]
#[derive(Debug)]
pub struct DecodeError;

#[cfg(feature = "simple")]
impl From<DecodeError> for CheckError {
    fn from(_: DecodeError) -> CheckError {
        CheckError::InvalidFormat("invalid B64".into())
    }
}

#[cfg(feature = "simple")]
impl core::error::Error for DecodeError {}

#[cfg(feature = "simple")]
impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "decode error")
    }
}
