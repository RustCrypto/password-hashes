use std::{fmt, error};

#[cfg(feature="include_simple")]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CheckError {
    HashMismatch,
    InvalidFormat,
}

#[cfg(feature="include_simple")]
impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            CheckError::HashMismatch => "password hash mismatch",
            CheckError::InvalidFormat => "invalid `hashed_value` format",
        })
    }
}

#[cfg(feature="include_simple")]
impl error::Error for CheckError {
    fn description(&self) -> &str {
        match self {
            CheckError::HashMismatch => "password hash mismatch",
            CheckError::InvalidFormat => "invalid `hashed_value` format",
        }
    }
}
