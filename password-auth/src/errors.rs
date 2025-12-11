//! Error types.

use alloc::string::ToString;
use core::fmt;

/// Password hash parse errors.
// This type has no public constructor and deliberately keeps `phc::Error` out of the public API
// so we can upgrade the `phc` version without it being a breaking change
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ParseError(phc::Error);

impl ParseError {
    /// Create a new parse error.
    pub(crate) fn new(err: phc::Error) -> Self {
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

impl core::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.0)
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

impl core::error::Error for VerifyError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Parse(err) => Some(err),
            _ => None,
        }
    }
}
