//! Implementation of the `password-hash` crate API.

use crate::pbkdf2;
use base64ct::{Base64, Encoding};
use core::{
    convert::{TryFrom, TryInto},
    fmt::{self, Display},
    str::FromStr,
};
use hmac::Hmac;
use password_hash::{
    Decimal, HasherError, Ident, McfHasher, Output, ParamsError, ParamsString, PasswordHash,
    PasswordHasher, Salt,
};
use sha2::{Sha256, Sha512};

#[cfg(feature = "sha1")]
use sha1::Sha1;

/// PBKDF2 (SHA-1)
#[cfg(feature = "sha1")]
pub const PBKDF2_SHA1: Ident = Ident::new("pbkdf2");

/// PBKDF2 (SHA-256)
pub const PBKDF2_SHA256: Ident = Ident::new("pbkdf2-sha256");

/// PBKDF2 (SHA-512)
pub const PBKDF2_SHA512: Ident = Ident::new("pbkdf2-sha512");

/// PBKDF2 type for use with [`PasswordHasher`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(docsrs, doc(cfg(feature = "simple")))]
pub struct Pbkdf2;

impl PasswordHasher for Pbkdf2 {
    type Params = Params;

    fn hash_password<'a>(
        &self,
        password: &[u8],
        alg_id: Option<Ident<'a>>,
        version: Option<Decimal>,
        params: Params,
        salt: Salt<'a>,
    ) -> Result<PasswordHash<'a>, HasherError> {
        let algorithm = Algorithm::try_from(alg_id.unwrap_or(PBKDF2_SHA256))?;

        if version.is_some() {
            return Err(HasherError::Version);
        }

        let mut salt_arr = [0u8; 64];
        let salt_bytes = salt.b64_decode(&mut salt_arr)?;

        let output = Output::init_with(params.output_length, |out| {
            let f = match algorithm {
                #[cfg(feature = "sha1")]
                Algorithm::Pbkdf2Sha1 => pbkdf2::<Hmac<Sha1>>,
                Algorithm::Pbkdf2Sha256 => pbkdf2::<Hmac<Sha256>>,
                Algorithm::Pbkdf2Sha512 => pbkdf2::<Hmac<Sha512>>,
            };

            f(password, salt_bytes, params.rounds, out);
            Ok(())
        })?;

        Ok(PasswordHash {
            algorithm: algorithm.ident(),
            version: None,
            params: params.try_into()?,
            salt: Some(salt),
            hash: Some(output),
        })
    }
}

/// PBKDF2 variants.
///
/// <https://en.wikipedia.org/wiki/PBKDF2>
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
#[cfg_attr(docsrs, doc(cfg(feature = "simple")))]
pub enum Algorithm {
    /// PBKDF2 SHA1
    #[cfg(feature = "sha1")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha1")))]
    Pbkdf2Sha1,

    /// PBKDF2 SHA-256
    Pbkdf2Sha256,

    /// PBKDF2 SHA-512
    Pbkdf2Sha512,
}

impl Algorithm {
    /// Parse an [`Algorithm`] from the provided string.
    pub fn new(id: impl AsRef<str>) -> Result<Self, HasherError> {
        id.as_ref().parse()
    }

    /// Get the [`Ident`] that corresponds to this PBKDF2 [`Algorithm`].
    pub fn ident(&self) -> Ident<'static> {
        match self {
            #[cfg(feature = "sha1")]
            Algorithm::Pbkdf2Sha1 => PBKDF2_SHA1,
            Algorithm::Pbkdf2Sha256 => PBKDF2_SHA256,
            Algorithm::Pbkdf2Sha512 => PBKDF2_SHA512,
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

impl Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Algorithm {
    type Err = HasherError;

    fn from_str(s: &str) -> Result<Algorithm, HasherError> {
        Ident::try_from(s)?.try_into()
    }
}

impl From<Algorithm> for Ident<'static> {
    fn from(alg: Algorithm) -> Ident<'static> {
        alg.ident()
    }
}

impl<'a> TryFrom<Ident<'a>> for Algorithm {
    type Error = HasherError;

    fn try_from(ident: Ident<'a>) -> Result<Algorithm, HasherError> {
        match ident {
            #[cfg(feature = "sha1")]
            PBKDF2_SHA1 => Ok(Algorithm::Pbkdf2Sha1),
            PBKDF2_SHA256 => Ok(Algorithm::Pbkdf2Sha256),
            PBKDF2_SHA512 => Ok(Algorithm::Pbkdf2Sha512),
            _ => Err(HasherError::Algorithm),
        }
    }
}

/// PBKDF2 params
#[cfg_attr(docsrs, doc(cfg(feature = "simple")))]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Params {
    /// Number of rounds
    pub rounds: u32,

    /// Size of the output (in bytes)
    pub output_length: usize,
}

impl Default for Params {
    fn default() -> Params {
        Params {
            rounds: 10_000,
            output_length: 32,
        }
    }
}

impl TryFrom<&ParamsString> for Params {
    type Error = HasherError;

    fn try_from(input: &ParamsString) -> Result<Self, HasherError> {
        let mut output = Params::default();

        for (ident, value) in input.iter() {
            match ident.as_str() {
                "i" => output.rounds = value.decimal()?,
                "l" => {
                    output.output_length = value
                        .decimal()?
                        .try_into()
                        .map_err(|_| ParamsError::InvalidValue)?
                }
                _ => return Err(ParamsError::InvalidName.into()),
            }
        }

        Ok(output)
    }
}

impl<'a> TryFrom<Params> for ParamsString {
    type Error = HasherError;

    fn try_from(input: Params) -> Result<ParamsString, HasherError> {
        let mut output = ParamsString::new();
        output.add_decimal("i", input.rounds)?;
        output.add_decimal("l", input.output_length as u32)?;
        Ok(output)
    }
}

impl McfHasher for Pbkdf2 {
    fn upgrade_mcf_hash<'a>(&self, hash: &'a str) -> Result<PasswordHash<'a>, HasherError> {
        use password_hash::ParseError;

        let mut parts = hash.split('$');

        // prevent dynamic allocations by using a fixed-size buffer
        let buf = [
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ];

        // check the format of the input: there may be no tokens before the first
        // and after the last `$`, tokens must have correct information and length.
        let (rounds, salt, hash) = match buf {
            [Some(""), Some("rpbkdf2"), Some("0"), Some(count), Some(salt), Some(hash), Some(""), None] =>
            {
                let mut count_arr = [0u8; 4];

                if Base64::decode(count, &mut count_arr)?.len() != 4 {
                    return Err(ParamsError::InvalidValue.into());
                }

                let count = u32::from_be_bytes(count_arr);
                (count, salt, hash)
            }
            _ => {
                // TODO(tarcieri): better errors here?
                return Err(ParseError::InvalidChar('?').into());
            }
        };

        let salt = Salt::new(b64_strip(salt))?;
        let hash = Output::b64_decode(b64_strip(hash))?;

        let params = Params {
            rounds,
            output_length: hash.len(),
        };

        Ok(PasswordHash {
            algorithm: PBKDF2_SHA256,
            version: None,
            params: params.try_into()?,
            salt: Some(salt),
            hash: Some(hash),
        })
    }
}

/// Strip trailing `=` signs off a Base64 value to make a valid B64 value
pub fn b64_strip(mut s: &str) -> &str {
    while s.ends_with('=') {
        s = &s[..(s.len() - 1)]
    }
    s
}
