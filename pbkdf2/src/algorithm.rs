use core::fmt::{self, Display};

#[cfg(feature = "phc")]
use password_hash::phc::Ident;
#[cfg(feature = "password-hash")]
use {core::str::FromStr, password_hash::Error};

/// PBKDF2 variants.
///
/// <https://en.wikipedia.org/wiki/PBKDF2>
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Algorithm {
    /// PBKDF2-HMAC-SHA1 a.k.a. `$pbkdf2`
    #[cfg(feature = "sha1")]
    Pbkdf2Sha1,

    /// PBKDF2-HMAC-SHA-256 a.k.a. `$pbkdf2-sha256`
    #[cfg(feature = "sha2")]
    Pbkdf2Sha256,

    /// PBKDF2-HMAC-SHA-512 a.k.a. `$pbkdf2-sha512`
    #[cfg(feature = "sha2")]
    Pbkdf2Sha512,
}

impl Algorithm {
    /// PBKDF2 (SHA-1) algorithm identifier
    #[cfg(feature = "sha1")]
    pub const PBKDF2_SHA1_ID: &'static str = "pbkdf2";

    /// PBKDF2 (SHA-256) algorithm identifier
    #[cfg(feature = "sha2")]
    pub const PBKDF2_SHA256_ID: &'static str = "pbkdf2-sha256";

    /// PBKDF2 (SHA-512) algorithm identifier
    #[cfg(feature = "sha2")]
    pub const PBKDF2_SHA512_ID: &'static str = "pbkdf2-sha512";

    /// PBKDF2 (SHA-1) algorithm identifier
    #[cfg(all(feature = "phc", feature = "sha1"))]
    pub(crate) const PBKDF2_SHA1_IDENT: Ident = Ident::new_unwrap(Self::PBKDF2_SHA1_ID);

    /// PBKDF2 (SHA-256) algorithm identifier
    #[cfg(feature = "phc")]
    pub(crate) const PBKDF2_SHA256_IDENT: Ident = Ident::new_unwrap(Self::PBKDF2_SHA256_ID);

    /// PBKDF2 (SHA-512) algorithm identifier
    #[cfg(feature = "phc")]
    pub(crate) const PBKDF2_SHA512_IDENT: Ident = Ident::new_unwrap(Self::PBKDF2_SHA512_ID);

    /// Default algorithm suggested by the [OWASP cheat sheet]:
    ///
    /// > Use PBKDF2 with a work factor of 600,000 or more and set with an
    /// > internal hash function of HMAC-SHA-256.
    ///
    /// [OWASP cheat sheet]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    #[cfg(feature = "sha2")]
    pub const RECOMMENDED: Self = Self::Pbkdf2Sha256;

    /// Parse an [`Algorithm`] from the provided string.
    #[cfg(feature = "password-hash")]
    pub fn new(id: impl AsRef<str>) -> password_hash::Result<Self> {
        id.as_ref().parse()
    }

    /// Get the Modular Crypt Format algorithm identifier for this algorithm.
    pub const fn to_str(self) -> &'static str {
        match self {
            #[cfg(feature = "sha1")]
            Algorithm::Pbkdf2Sha1 => Self::PBKDF2_SHA1_ID,
            #[cfg(feature = "sha2")]
            Algorithm::Pbkdf2Sha256 => Self::PBKDF2_SHA256_ID,
            #[cfg(feature = "sha2")]
            Algorithm::Pbkdf2Sha512 => Self::PBKDF2_SHA512_ID,
        }
    }
}

impl AsRef<str> for Algorithm {
    fn as_ref(&self) -> &str {
        self.to_str()
    }
}

#[cfg(feature = "sha2")]
impl Default for Algorithm {
    fn default() -> Self {
        Self::RECOMMENDED
    }
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_str())
    }
}

#[cfg(feature = "password-hash")]
impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> password_hash::Result<Algorithm> {
        s.try_into()
    }
}

#[cfg(feature = "phc")]
impl From<Algorithm> for Ident {
    fn from(alg: Algorithm) -> Ident {
        match alg {
            #[cfg(feature = "sha1")]
            Algorithm::Pbkdf2Sha1 => Algorithm::PBKDF2_SHA1_IDENT,
            Algorithm::Pbkdf2Sha256 => Algorithm::PBKDF2_SHA256_IDENT,
            Algorithm::Pbkdf2Sha512 => Algorithm::PBKDF2_SHA512_IDENT,
        }
    }
}

#[cfg(feature = "password-hash")]
impl<'a> TryFrom<&'a str> for Algorithm {
    type Error = Error;

    fn try_from(name: &'a str) -> password_hash::Result<Algorithm> {
        match name {
            #[cfg(feature = "sha1")]
            Self::PBKDF2_SHA1_ID => Ok(Algorithm::Pbkdf2Sha1),
            #[cfg(feature = "sha2")]
            Self::PBKDF2_SHA256_ID => Ok(Algorithm::Pbkdf2Sha256),
            #[cfg(feature = "sha2")]
            Self::PBKDF2_SHA512_ID => Ok(Algorithm::Pbkdf2Sha512),
            _ => Err(Error::Algorithm),
        }
    }
}
