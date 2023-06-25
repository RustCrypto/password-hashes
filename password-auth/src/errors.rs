//! Error types.

use alloc::string::ToString;
use core::fmt;

/// Password hash parse errors.
// This type has no public constructor and deliberately keeps
// `password_hash::Error` out of the public API so it can evolve
// independently (e.g. get to 1.0 faster)
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ParseError(password_hash::Error);

impl ParseError {
    /// Create a new parse error.
    pub(crate) fn new(err: password_hash::Error) -> Self {
        Self(err)
    }
}

impl fmt::Debug for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ParseError")
            .field(&self.0.to_string())
            .finish()
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.0)
    }
}

/// Password verification errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyError {
    /// Password hash parsing errors.
    Parse(ParseError),

    /// Password is invalid.
    PasswordInvalid,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(err) => write!(f, "{err}"),
            Self::PasswordInvalid => write!(f, "password is invalid"),
        }
    }
}

impl From<ParseError> for VerifyError {
    fn from(err: ParseError) -> VerifyError {
        VerifyError::Parse(err)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

#[cfg(feature = "std")]
impl std::error::Error for VerifyError {}
