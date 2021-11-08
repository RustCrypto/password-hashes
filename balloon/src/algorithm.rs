//! Balloon algorithms (e.g. Balloon, BalloonM).

use crate::{Error, Result};
use core::{
    fmt::{self, Display},
    str::FromStr,
};

#[cfg(feature = "password-hash")]
use {core::convert::TryFrom, password_hash::Ident};

/// Balloon primitive type: variants of the algorithm.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum Algorithm {
    /// Standard Balloon hashing algorithm.
    Balloon,

    /// M-core variant of the Balloon hashing algorithm.
    ///
    /// Supports parallelism by computing M instances of the
    /// single-core Balloon function and XORing all the outputs.
    BalloonM,
}

impl Default for Algorithm {
    fn default() -> Algorithm {
        Algorithm::BalloonM
    }
}

impl Algorithm {
    /// Balloon algorithm identifier
    #[cfg(feature = "password-hash")]
    #[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
    pub const BALLOON_IDENT: Ident<'static> = Ident::new("balloon");

    /// BalloonM algorithm identifier
    #[cfg(feature = "password-hash")]
    #[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
    pub const BALLOON_M_IDENT: Ident<'static> = Ident::new("balloon-m");

    /// Parse an [`Algorithm`] from the provided string.
    pub fn new(id: impl AsRef<str>) -> Result<Self> {
        id.as_ref().parse()
    }

    /// Get the identifier string for this Balloon [`Algorithm`].
    pub fn as_str(&self) -> &str {
        match self {
            Algorithm::Balloon => "balloon",
            Algorithm::BalloonM => "balloon-m",
        }
    }

    /// Get the [`Ident`] that corresponds to this Balloon [`Algorithm`].
    #[cfg(feature = "password-hash")]
    #[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
    pub fn ident(&self) -> Ident<'static> {
        match self {
            Algorithm::Balloon => Self::BALLOON_IDENT,
            Algorithm::BalloonM => Self::BALLOON_M_IDENT,
        }
    }
}

impl AsRef<str> for Algorithm {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Algorithm> {
        match s {
            "balloon" => Ok(Algorithm::Balloon),
            "balloon-m" => Ok(Algorithm::BalloonM),
            _ => Err(Error::AlgorithmInvalid),
        }
    }
}

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl From<Algorithm> for Ident<'static> {
    fn from(alg: Algorithm) -> Ident<'static> {
        alg.ident()
    }
}

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl<'a> TryFrom<Ident<'a>> for Algorithm {
    type Error = password_hash::Error;

    fn try_from(ident: Ident<'a>) -> password_hash::Result<Algorithm> {
        match ident {
            Self::BALLOON_IDENT => Ok(Algorithm::Balloon),
            Self::BALLOON_M_IDENT => Ok(Algorithm::BalloonM),
            _ => Err(password_hash::Error::Algorithm),
        }
    }
}
