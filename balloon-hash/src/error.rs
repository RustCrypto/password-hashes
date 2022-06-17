//! Error type

use core::fmt;

#[cfg(feature = "password-hash")]
use ::{core::cmp::Ordering, password_hash::errors::InvalidValue};

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
                write!(f, "unexpected output size, expected {} bytes", expected)
            }
        }
    }
}

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl From<Error> for password_hash::Error {
    fn from(err: Error) -> password_hash::Error {
        match err {
            Error::AlgorithmInvalid => password_hash::Error::Algorithm,
            Error::MemoryTooLittle => InvalidValue::TooShort.param_error(),
            Error::ThreadsTooFew => InvalidValue::TooShort.param_error(),
            Error::ThreadsTooMany => InvalidValue::TooLong.param_error(),
            Error::TimeTooSmall => InvalidValue::TooShort.param_error(),
            Error::OutputSize { actual, expected } => match actual.cmp(&expected) {
                Ordering::Less => password_hash::Error::OutputTooShort,
                Ordering::Greater => password_hash::Error::OutputTooLong,
                Ordering::Equal => unreachable!("unexpected correct output size"),
            },
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
