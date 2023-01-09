#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![warn(
    clippy::checked_conversions,
    clippy::integer_arithmetic,
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

use alloc::string::{String, ToString};
use core::fmt;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand_core::OsRng;

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

/// Opaque error type.
#[derive(Clone, Copy, Debug)]
pub struct VerifyError;

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("password verification error")
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for VerifyError {}

/// Generate a password hash for the given password.
pub fn generate_hash(password: impl AsRef<[u8]>) -> String {
    let salt = SaltString::generate(OsRng);
    generate_phc_hash(password.as_ref(), &salt)
        .map(|hash| hash.to_string())
        .expect("password hashing error")
}

/// Generate a PHC hash using the preferred algorithm.
#[allow(unreachable_code)]
fn generate_phc_hash<'a>(
    password: &[u8],
    salt: &'a SaltString,
) -> password_hash::Result<PasswordHash<'a>> {
    //
    // Algorithms below are in order of preference
    //
    #[cfg(feature = "argon2")]
    return Argon2::default().hash_password(password, salt);

    #[cfg(feature = "scrypt")]
    return Scrypt.hash_password(password, salt);

    #[cfg(feature = "pbkdf2")]
    return Pbkdf2.hash_password(password, salt);
}

/// Verify the provided password against the provided password hash.
pub fn verify_password(password: impl AsRef<[u8]>, hash: &str) -> Result<(), VerifyError> {
    let hash = PasswordHash::new(hash).map_err(|_| VerifyError)?;

    let algs: &[&dyn PasswordVerifier] = &[
        #[cfg(feature = "argon2")]
        &Argon2::default(),
        #[cfg(feature = "pbkdf2")]
        &Pbkdf2,
        #[cfg(feature = "scrypt")]
        &Scrypt,
    ];

    hash.verify_password(algs, password)
        .map_err(|_| VerifyError)
}

#[cfg(test)]
mod tests {
    use super::{generate_hash, verify_password};

    const EXAMPLE_PASSWORD: &str = "password";

    #[test]
    fn happy_path() {
        let hash = generate_hash(EXAMPLE_PASSWORD);
        assert!(verify_password(EXAMPLE_PASSWORD, &hash).is_ok());
        assert!(verify_password("bogus", &hash).is_err());
    }

    #[cfg(feature = "argon2")]
    mod argon2 {
        use super::{verify_password, EXAMPLE_PASSWORD};

        /// Argon2 hash for the string "password".
        const EXAMPLE_HASH: &str =
            "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQAAAAAAAAAAA$+r0d29hqEB0yasKr55ZgICsQGSkl0v0kgwhd+U3wyRo";

        #[test]
        fn verify() {
            assert!(verify_password(EXAMPLE_PASSWORD, EXAMPLE_HASH).is_ok());
            assert!(verify_password("bogus", EXAMPLE_HASH).is_err());
        }
    }

    #[cfg(feature = "pbkdf2")]
    mod pdkdf2 {
        use super::{verify_password, EXAMPLE_PASSWORD};

        /// PBKDF2 hash for the string "password".
        const EXAMPLE_HASH: &str =
            "$pbkdf2-sha256$i=4096,l=32$c2FsdA$xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o";

        #[test]
        fn verify() {
            assert!(verify_password(EXAMPLE_PASSWORD, EXAMPLE_HASH).is_ok());
            assert!(verify_password("bogus", EXAMPLE_HASH).is_err());
        }
    }

    #[cfg(feature = "scrypt")]
    mod scrypt {
        use super::{verify_password, EXAMPLE_PASSWORD};

        /// scrypt hash for the string "password".
        const EXAMPLE_HASH: &str =
            "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";

        #[test]
        fn verify() {
            assert!(verify_password(EXAMPLE_PASSWORD, EXAMPLE_HASH).is_ok());
            assert!(verify_password("bogus", EXAMPLE_HASH).is_err());
        }
    }
}
