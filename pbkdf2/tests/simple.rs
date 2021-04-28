//! Tests for `password-hash` crate integration.
//!
//! PBKDF2-SHA256 vectors adapted from: https://stackoverflow.com/a/5136918

#![cfg(feature = "simple")]

use hex_literal::hex;
use pbkdf2::{
    password_hash::{McfHasher, PasswordHasher, Salt},
    Algorithm, Params, Pbkdf2,
};
use std::convert::TryFrom;

const PASSWORD: &str = "password";
const SALT_B64: &str = "c2FsdA"; // "salt"

/// Test with `algorithm: None` - uses default PBKDF2-SHA256
#[test]
fn hash_with_default_algorithm() {
    // Input:
    //   P = "password" (8 octets)
    //   S = "salt" (4 octets)
    //   c = 4096
    //   dkLen = 32
    let salt = Salt::new(SALT_B64).unwrap();

    let params = Params {
        rounds: 4096,
        output_length: 32,
    };

    let hash = Pbkdf2
        .hash_password(PASSWORD.as_bytes(), None, params, salt)
        .unwrap();

    assert_eq!(hash.algorithm, Algorithm::Pbkdf2Sha256.ident());
    assert_eq!(hash.salt.unwrap().as_str(), SALT_B64);
    assert_eq!(Params::try_from(&hash).unwrap(), params);

    let expected_output = hex!("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
    assert_eq!(hash.hash.unwrap().as_ref(), expected_output);
}

#[test]
fn upgrade_mcf_hash() {
    let mcf_hash = "$rpbkdf2$0$AAAEAA==$w7Y1w07wETYY7CXw5W07TA==$wRwXwI/764oNt1HvTeQcIrqr9rfzfq/KySgcCROy1HU=$";
    let phc_hash = Pbkdf2.upgrade_mcf_hash(&mcf_hash).unwrap();

    assert_eq!(phc_hash.algorithm, Algorithm::Pbkdf2Sha256.ident());

    let params = Params::try_from(&phc_hash).unwrap();
    assert_eq!(params.rounds, 1024);
    assert_eq!(params.output_length, 32);
    assert_eq!(
        Pbkdf2.verify_mcf_hash(PASSWORD.as_bytes(), &mcf_hash),
        Ok(())
    );
}
