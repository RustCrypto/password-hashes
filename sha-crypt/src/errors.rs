//! Error types.

use alloc::string;

#[cfg(feature = "simple")]
use alloc::string::String;

#[cfg(feature = "std")]
use std::io;

/// Error type.
#[derive(Debug)]
pub enum CryptError {
    /// Should be within range defs::ROUNDS_MIN < defs::ROUNDS_MIN
    RoundsError,

    /// RNG failed.
    RandomError,

    /// I/O error.
    #[cfg(feature = "std")]
    IoError(io::Error),

    /// UTF-8 error.
    StringError(string::FromUtf8Error),
}

#[cfg(feature = "std")]
impl From<io::Error> for CryptError {
    fn from(e: io::Error) -> Self {
        CryptError::IoError(e)
    }
}

impl From<string::FromUtf8Error> for CryptError {
    fn from(e: string::FromUtf8Error) -> Self {
        CryptError::StringError(e)
    }
}

#[cfg(feature = "simple")]
#[derive(Debug)]
pub enum CheckError {
    InvalidFormat(String),
    Crypt(CryptError),
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
