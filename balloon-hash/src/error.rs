//! Error type

use core::fmt;

/// Result with balloon's [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Algorithm identifier invalid.
    AlgorithmInvalid,
    /// Memory cost is too small.
    MemoryTooLittle,
    /// Not enough threads.
    ThreadsTooFew,
    /// Too many threads.
    ThreadsTooMany,
    /// Time cost is too small.
    TimeTooSmall,
    /// Output size not correct.
    OutputSize {
        /// Output size provided.
        actual: usize,
        /// Output size expected.
        expected: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AlgorithmInvalid => f.write_str("algorithm identifier invalid"),
            Error::MemoryTooLittle => f.write_str("memory cost is too small"),
            Error::ThreadsTooFew => f.write_str("not enough threads"),
            Error::ThreadsTooMany => f.write_str("too many threads"),
            Error::TimeTooSmall => f.write_str("time cost is too small"),
            Error::OutputSize { expected, .. } => {
                write!(f, "unexpected output size, expected {expected} bytes")
            }
        }
    }
}

#[cfg(feature = "password-hash")]
impl From<Error> for password_hash::Error {
    fn from(err: Error) -> password_hash::Error {
        match err {
            Error::AlgorithmInvalid => password_hash::Error::Algorithm,
            Error::MemoryTooLittle
            | Error::ThreadsTooFew
            | Error::ThreadsTooMany
            | Error::TimeTooSmall => password_hash::Error::ParamsInvalid,
            Error::OutputSize { .. } => password_hash::Error::OutputSize,
        }
    }
}

impl core::error::Error for Error {}
