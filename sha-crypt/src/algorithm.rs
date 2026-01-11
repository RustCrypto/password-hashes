use core::{fmt, str::FromStr};
use password_hash::Error;

/// SHA-crypt algorithm variants: SHA-256 or SHA-512.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Algorithm {
    /// SHA-256-crypt: SHA-crypt instantiated with SHA-256.
    Sha256Crypt,

    /// SHA-512-crypt: SHA-crypt instantiated with SHA-512.
    Sha512Crypt,
}

impl Default for Algorithm {
    /// Recommended default algorithm: SHA-512.
    fn default() -> Self {
        Self::RECOMMENDED
    }
}

impl Algorithm {
    /// SHA-256-crypt Modular Crypt Format algorithm identifier
    pub const SHA256_CRYPT_IDENT: &str = "5";

    /// SHA-512-crypt Modular Crypt Format algorithm identifier
    pub const SHA512_CRYPT_IDENT: &str = "6";

    /// Recommended default algorithm: SHA-512.
    const RECOMMENDED: Self = Self::Sha512Crypt;

    /// Parse an [`Algorithm`] from the provided string.
    pub fn new(id: impl AsRef<str>) -> password_hash::Result<Self> {
        id.as_ref().parse()
    }

    /// Get the Modular Crypt Format algorithm identifier for this algorithm.
    pub const fn ident(&self) -> &'static str {
        match self {
            Algorithm::Sha256Crypt => Self::SHA256_CRYPT_IDENT,
            Algorithm::Sha512Crypt => Self::SHA512_CRYPT_IDENT,
        }
    }

    /// Get the identifier string for this PBKDF2 [`Algorithm`].
    pub fn as_str(&self) -> &'static str {
        self.ident()
    }
}

impl AsRef<str> for Algorithm {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> password_hash::Result<Algorithm> {
        s.try_into()
    }
}

impl<'a> TryFrom<&'a str> for Algorithm {
    type Error = Error;

    fn try_from(name: &'a str) -> password_hash::Result<Algorithm> {
        match name {
            Self::SHA256_CRYPT_IDENT => Ok(Algorithm::Sha256Crypt),
            Self::SHA512_CRYPT_IDENT => Ok(Algorithm::Sha512Crypt),
            _ => Err(Error::Algorithm),
        }
    }
}
