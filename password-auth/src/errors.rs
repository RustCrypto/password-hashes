//! Error types.

use core::fmt;

/// Password hash parse errors.
#[derive(Clone, Copy, Debug)]
pub struct ParseError(password_hash::Error);

impl ParseError {
    /// Create a new parse error.
    pub(crate) fn new(err: password_hash::Error) -> Self {
        Self(err)
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

/// Password hash verification errors.
#[derive(Clone, Copy, Debug)]
pub struct VerifyError;

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("password verification error")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerifyError {}
