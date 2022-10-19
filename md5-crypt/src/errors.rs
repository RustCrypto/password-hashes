//! Error types.

#[cfg(feature = "alloc")]
use alloc::string;

/// Error type.
#[derive(Debug)]
pub enum CryptError {
    /// RNG failed.
    RandomError,

    /// UTF-8 error.
    #[cfg(feature = "alloc")]
    StringError(string::FromUtf8Error),
}

#[cfg(feature = "alloc")]
impl From<string::FromUtf8Error> for CryptError {
    fn from(e: string::FromUtf8Error) -> Self {
        CryptError::StringError(e)
    }
}

#[derive(Debug)]
pub enum CheckError {
    InvalidFormat(&'static str),
    #[cfg(feature = "subtle")]
    Crypt(CryptError),
    #[cfg(feature = "subtle")]
    HashMismatch,
}

/// Decoding errors.
#[cfg_attr(docsrs, doc(cfg(feature = "simple")))]
#[derive(Debug)]
pub struct DecodeError;

impl From<DecodeError> for CheckError {
    fn from(_: DecodeError) -> CheckError {
        CheckError::InvalidFormat("invalid B64")
    }
}
