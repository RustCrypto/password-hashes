//! Error types.

use alloc::string;

#[cfg(feature = "simple")]
use alloc::string::String;

#[cfg(feature = "std")]
use std::io;

#[derive(Debug)]
pub enum CryptError {
    /// Should be within range defs::ROUNDS_MIN < defs::ROUNDS_MIN
    RoundsError,
    RandomError,
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    IoError(io::Error),
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
#[cfg_attr(docsrs, doc(cfg(feature = "simple")))]
#[derive(Debug)]
pub enum CheckError {
    InvalidFormat(String),
    Crypt(CryptError),
    HashMismatch,
}
