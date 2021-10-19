//! Error type

use core::fmt;

#[cfg(feature = "password-hash")]
use password_hash::errors::InvalidValue;

/// Result with balloon's [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Memory cost is too small.
    MemoryTooLittle,
    /// Not enough threads.
    ThreadsTooFew,
    /// Time cost is too small.
    TimeTooSmall,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::MemoryTooLittle => "memory cost is too small",
            Error::ThreadsTooFew => "not enough threads",
            Error::TimeTooSmall => "time cost is too small",
        })
    }
}

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl From<Error> for password_hash::Error {
    fn from(err: Error) -> password_hash::Error {
        match err {
            Error::MemoryTooLittle => InvalidValue::TooShort.param_error(),
            Error::ThreadsTooFew => InvalidValue::TooShort.param_error(),
            Error::TimeTooSmall => InvalidValue::TooShort.param_error(),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
