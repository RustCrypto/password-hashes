use std::{fmt, error};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct InvalidOutputLen;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct InvalidParams;

#[cfg(feature="include_simple")]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CheckError {
    HashMismatch,
    InvalidFormat,
}

impl fmt::Display for InvalidOutputLen {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid output buffer length")
    }
}

impl error::Error for InvalidOutputLen {
    fn description(&self) -> &str { "invalid output buffer length" }
}

impl fmt::Display for InvalidParams {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid scrypt parameters")
    }
}

impl error::Error for InvalidParams {
    fn description(&self) -> &str { "invalid scrypt parameters" }
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            CheckError::HashMismatch => "password hash mismatch",
            CheckError::InvalidFormat => "invalid `hashed_value` format",
        })
    }
}

impl error::Error for CheckError {
    fn description(&self) -> &str {
        match self {
            CheckError::HashMismatch => "password hash mismatch",
            CheckError::InvalidFormat => "invalid `hashed_value` format",
        }
    }
}
