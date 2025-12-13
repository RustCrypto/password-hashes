#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![warn(
    clippy::checked_conversions,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod errors;

pub use crate::errors::{ParseError, VerifyError};

use alloc::string::{String, ToString};
use password_hash::{
    PasswordHasher, PasswordVerifier,
    phc::{ParamsString, PasswordHash},
};

#[cfg(not(any(feature = "argon2", feature = "pbkdf2", feature = "scrypt")))]
compile_error!(
    "please enable at least one password hash crate feature, e.g. argon2, pbkdf2, scrypt"
);

#[cfg(feature = "argon2")]
use argon2::Argon2;
#[cfg(feature = "pbkdf2")]
use pbkdf2::Pbkdf2;
#[cfg(feature = "scrypt")]
use scrypt::Scrypt;

/// Generate a password hash for the given password.
///
/// Uses the best available password hashing algorithm given the enabled
/// crate features (typically Argon2 unless explicitly disabled).
pub fn generate_hash(password: impl AsRef<[u8]>) -> String {
    generate_phc_hash(password.as_ref())
        .as_ref()
        .map(ToString::to_string)
        .expect("password hashing error")
}

/// Generate a PHC hash using the preferred algorithm.
#[allow(unreachable_code)]
fn generate_phc_hash(password: &[u8]) -> password_hash::Result<PasswordHash> {
    //
    // Algorithms below are in order of preference
    //
    #[cfg(feature = "argon2")]
    return Argon2::default().hash_password(password);

    #[cfg(feature = "scrypt")]
    return Scrypt.hash_password(password);

    #[cfg(feature = "pbkdf2")]
    return Pbkdf2.hash_password(password);
}

/// Verify the provided password against the provided password hash.
///
/// # Returns
///
/// - `Ok(())` if the password hash verified successfully
/// - `Err(VerifyError)` if the hash didn't parse successfully or the password
///   failed to verify against the hash.
pub fn verify_password(password: impl AsRef<[u8]>, hash: &str) -> Result<(), VerifyError> {
    let hash = PasswordHash::new(hash).map_err(ParseError::new)?;

    let algs: &[&dyn PasswordVerifier<PasswordHash>] = &[
        #[cfg(feature = "argon2")]
        &Argon2::default(),
        #[cfg(feature = "pbkdf2")]
        &Pbkdf2,
        #[cfg(feature = "scrypt")]
        &Scrypt,
    ];

    for &alg in algs {
        if alg.verify_password(password.as_ref(), &hash).is_ok() {
            return Ok(());
        }
    }

    Err(VerifyError::PasswordInvalid)
}

/// Determine if the given password hash is using the recommended algorithm and
/// parameters.
///
/// This can be used by implementations which wish to lazily update their
/// password hashes (i.e. by rehashing the password with [`generate_hash`])
/// to determine if such an update should be applied.
///
/// # Returns
/// - `Ok(true)` if the hash *isn't* using the latest recommended algorithm/parameters.
/// - `Ok(false)` if the hash *is* using the latest recommended algorithm/parameters.
/// - `Err(ParseError)` if the hash could not be parsed.
#[allow(unreachable_code)]
pub fn is_hash_obsolete(hash: &str) -> Result<bool, ParseError> {
    let hash = PasswordHash::new(hash).map_err(ParseError::new)?;

    #[cfg(feature = "argon2")]
    return Ok(hash.algorithm != argon2::Algorithm::default().ident()
        || hash.params != default_params_string::<argon2::Params>());

    #[cfg(feature = "scrypt")]
    return Ok(hash.algorithm != scrypt::ALG_ID
        || hash.params != default_params_string::<scrypt::Params>());

    #[cfg(feature = "pbkdf2")]
    return Ok(hash.algorithm != *pbkdf2::Algorithm::default().ident()
        || hash.params != default_params_string::<pbkdf2::Params>());

    Ok(true)
}

fn default_params_string<T>() -> ParamsString
where
    T: Default + TryInto<ParamsString, Error = password_hash::Error>,
{
    T::default().try_into().expect("invalid default params")
}

#[cfg(test)]
mod tests {
    use super::{generate_hash, is_hash_obsolete, verify_password};

    const EXAMPLE_PASSWORD: &str = "password";

    #[test]
    fn happy_path() {
        let hash = generate_hash(EXAMPLE_PASSWORD);
        assert!(verify_password(EXAMPLE_PASSWORD, &hash).is_ok());
        assert!(verify_password("bogus", &hash).is_err());
        assert!(!is_hash_obsolete(&hash).expect("hash can be parsed"));
    }

    #[cfg(feature = "argon2")]
    mod argon2 {
        use super::{EXAMPLE_PASSWORD, verify_password};

        /// Argon2 hash for the string "password".
        const EXAMPLE_HASH: &str = "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQAAAAAAAAAAA$+r0d29hqEB0yasKr55ZgICsQGSkl0v0kgwhd+U3wyRo";

        #[test]
        fn verify() {
            assert!(verify_password(EXAMPLE_PASSWORD, EXAMPLE_HASH).is_ok());
            assert!(verify_password("bogus", EXAMPLE_HASH).is_err());
        }
    }

    #[cfg(feature = "pbkdf2")]
    mod pdkdf2 {
        use super::verify_password;

        /// PBKDF2 password test vector from the `pbkdf2` crate
        const EXAMPLE_PASSWORD: &[u8] = b"passwordPASSWORDpassword";

        /// PBKDF2 hash test vector from the `pbkdf2` crate
        const EXAMPLE_HASH: &str = "$pbkdf2-sha256$i=4096,l=40\
            $c2FsdFNBTFRzYWx0U0FMVHNhbHRTQUxUc2FsdFNBTFRzYWx0\
            $NIyJ28vTKy8y2BS4EW6EzysXNH68GAAYHE4qH7jdU+HGNVGMfaxH6Q";

        #[test]
        fn verify() {
            assert!(verify_password(EXAMPLE_PASSWORD, EXAMPLE_HASH).is_ok());
            assert!(verify_password("bogus", EXAMPLE_HASH).is_err());
        }
    }

    #[cfg(feature = "scrypt")]
    mod scrypt {
        use super::{EXAMPLE_PASSWORD, verify_password};

        /// scrypt hash for the string "password".
        const EXAMPLE_HASH: &str = "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";

        #[test]
        fn verify() {
            assert!(verify_password(EXAMPLE_PASSWORD, EXAMPLE_HASH).is_ok());
            assert!(verify_password("bogus", EXAMPLE_HASH).is_err());
        }
    }
}
