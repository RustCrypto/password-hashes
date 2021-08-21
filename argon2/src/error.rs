//! Error type

#[cfg(feature = "std")]
extern crate std;

use core::fmt;

/// Error type.
// TODO(tarcieri): consolidate/replace with `password_hash::Error`
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Associated data is too long
    AdTooLong,

    /// Algorithm identifier invalid
    AlgorithmInvalid,

    /// Too few lanes
    LanesTooFew,

    /// Too many lanes
    LanesTooMany,

    /// Memory cost is too small
    MemoryTooLittle,

    /// Memory cost is too large
    MemoryTooMuch,

    /// Output is too short
    OutputTooShort,

    /// Output is too long
    OutputTooLong,

    /// Password is too long
    PwdTooLong,

    /// Salt is too short
    SaltTooShort,

    /// Salt is too long
    SaltTooLong,

    /// Secret is too long
    SecretTooLong,

    /// Not enough threads
    ThreadsTooFew,

    /// Too many threads
    ThreadsTooMany,

    /// Time cost is too small
    TimeTooSmall,

    /// Invalid version
    VersionInvalid,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::AdTooLong => "associated data is too long",
            Error::AlgorithmInvalid => "algorithm identifier invalid",
            Error::LanesTooFew => "too few lanes",
            Error::LanesTooMany => "too many lanes",
            Error::MemoryTooLittle => "memory cost is too small",
            Error::MemoryTooMuch => "memory cost is too large",
            Error::OutputTooShort => "output is too short",
            Error::OutputTooLong => "output is too long",
            Error::PwdTooLong => "password is too long",
            Error::SaltTooShort => "salt is too short",
            Error::SaltTooLong => "salt is too long",
            Error::SecretTooLong => "secret is too long",
            Error::ThreadsTooFew => "not enough threads",
            Error::ThreadsTooMany => "too many threads",
            Error::TimeTooSmall => "time cost is too small",
            Error::VersionInvalid => "invalid version",
        })
    }
}

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl From<Error> for password_hash::Error {
    fn from(err: Error) -> password_hash::Error {
        match err {
            Error::AdTooLong => password_hash::Error::ParamValueInvalid,
            Error::AlgorithmInvalid => password_hash::Error::Algorithm,
            Error::LanesTooFew => password_hash::Error::ParamValueInvalid,
            Error::LanesTooMany => password_hash::Error::ParamValueInvalid,
            Error::MemoryTooLittle => password_hash::Error::ParamValueInvalid,
            Error::MemoryTooMuch => password_hash::Error::ParamValueInvalid,
            Error::PwdTooLong => password_hash::Error::Password,
            Error::OutputTooShort => password_hash::Error::OutputTooShort,
            Error::OutputTooLong => password_hash::Error::OutputTooLong,
            Error::SaltTooShort => password_hash::Error::SaltTooShort,
            Error::SaltTooLong => password_hash::Error::SaltTooLong,
            Error::SecretTooLong => password_hash::Error::ParamValueInvalid,
            Error::ThreadsTooFew => password_hash::Error::ParamValueInvalid,
            Error::ThreadsTooMany => password_hash::Error::ParamValueInvalid,
            Error::TimeTooSmall => password_hash::Error::ParamValueInvalid,
            Error::VersionInvalid => password_hash::Error::Version,
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
