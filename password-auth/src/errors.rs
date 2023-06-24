//! Error types.

use alloc::string::ToString;
use core::fmt;

/// Error type.
#[derive(Clone, Copy, Debug)]
pub enum Error {
    /// Password hash parsing errors.
    Parse(ParseError),

    /// Password is invalid.
    PasswordInvalid,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(err) => write!(f, "{err}"),
            Self::PasswordInvalid => write!(f, "password is invalid"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<ParseError> for Error {
    fn from(err: ParseError) -> Error {
        Error::Parse(err)
    }
}

/// Password hash parse errors.
// This type has no public constructor and deliberately keeps
// `password_hash::Error` out of the public API so it can evolve
// independently (e.g. get to 1.0 faster)
#[derive(Clone, Copy)]
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

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}
