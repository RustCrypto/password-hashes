use rand;
use std::io;
use std::string;

#[derive(Debug)]
pub enum CryptError {
    /// Should be within range defs::ROUNDS_MIN < defs::ROUNDS_MIN
    RoundsError,
    IoError(io::Error),
    RandError(rand::Error),
    StringError(string::FromUtf8Error),
}

impl From<io::Error> for CryptError {
    fn from(e: io::Error) -> Self {
        CryptError::IoError(e)
    }
}

impl From<rand::Error> for CryptError {
    fn from(e: rand::Error) -> Self {
        CryptError::RandError(e)
    }
}

impl From<string::FromUtf8Error> for CryptError {
    fn from(e: string::FromUtf8Error) -> Self {
        CryptError::StringError(e)
    }
}

#[derive(Debug)]
pub enum CheckError {
    InvalidFormat(String),
    Crypt(CryptError),
    HashMismatch,
}
