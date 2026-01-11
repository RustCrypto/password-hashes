use core::{
    fmt::{self, Display},
    str::FromStr,
};
use password_hash::{Error, phc::Ident};

/// PBKDF2 variants.
///
/// <https://en.wikipedia.org/wiki/PBKDF2>
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Algorithm {
    /// PBKDF2 SHA1
    #[cfg(feature = "sha1")]
    Pbkdf2Sha1,

    /// PBKDF2 SHA-256
    Pbkdf2Sha256,

    /// PBKDF2 SHA-512
    Pbkdf2Sha512,
}

impl Algorithm {
    /// PBKDF2 (SHA-1) algorithm identifier
    #[cfg(feature = "sha1")]
    pub const PBKDF2_SHA1_IDENT: Ident = Ident::new_unwrap("pbkdf2");

    /// PBKDF2 (SHA-256) algorithm identifier
    pub const PBKDF2_SHA256_IDENT: Ident = Ident::new_unwrap("pbkdf2-sha256");

    /// PBKDF2 (SHA-512) algorithm identifier
    pub const PBKDF2_SHA512_IDENT: Ident = Ident::new_unwrap("pbkdf2-sha512");

    /// Default algorithm suggested by the [OWASP cheat sheet]:
    ///
    /// > Use PBKDF2 with a work factor of 600,000 or more and set with an
    /// > internal hash function of HMAC-SHA-256.
    ///
    /// [OWASP cheat sheet]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    pub const RECOMMENDED: Self = Self::Pbkdf2Sha256;

    /// Parse an [`Algorithm`] from the provided string.
    pub fn new(id: impl AsRef<str>) -> password_hash::Result<Self> {
        id.as_ref().parse()
    }

    /// Get the [`Ident`] that corresponds to this PBKDF2 [`Algorithm`].
    pub fn ident(&self) -> &'static Ident {
        match self {
            #[cfg(feature = "sha1")]
            Algorithm::Pbkdf2Sha1 => &Self::PBKDF2_SHA1_IDENT,
            Algorithm::Pbkdf2Sha256 => &Self::PBKDF2_SHA256_IDENT,
            Algorithm::Pbkdf2Sha512 => &Self::PBKDF2_SHA512_IDENT,
        }
    }

    /// Get the identifier string for this PBKDF2 [`Algorithm`].
    pub fn as_str(&self) -> &str {
        self.ident().as_str()
    }
}

impl AsRef<str> for Algorithm {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::RECOMMENDED
    }
}

impl Display for Algorithm {
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

impl From<Algorithm> for Ident {
    fn from(alg: Algorithm) -> Ident {
        *alg.ident()
    }
}

impl<'a> TryFrom<&'a str> for Algorithm {
    type Error = Error;

    fn try_from(name: &'a str) -> password_hash::Result<Algorithm> {
        match name.try_into() {
            #[cfg(feature = "sha1")]
            Ok(Self::PBKDF2_SHA1_IDENT) => Ok(Algorithm::Pbkdf2Sha1),
            Ok(Self::PBKDF2_SHA256_IDENT) => Ok(Algorithm::Pbkdf2Sha256),
            Ok(Self::PBKDF2_SHA512_IDENT) => Ok(Algorithm::Pbkdf2Sha512),
            _ => Err(Error::Algorithm),
        }
    }
}
