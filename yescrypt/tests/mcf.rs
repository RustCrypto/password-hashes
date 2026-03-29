//! Tests for encoding password hash strings in Modular Crypt Format (MCF).

#![cfg(feature = "password-hash")]

use yescrypt::{
    CustomizedPasswordHasher, Params, PasswordHashRef, PasswordVerifier, Yescrypt,
    password_hash::Error,
};

#[path = "../data/mcf_test_vectors.rs"]
mod test_vectors;
use test_vectors::MCF_TEST_VECTORS;

/// `yescrypt()` tests
#[test]
fn compute_reference_strings() {
    for test_vector in MCF_TEST_VECTORS {
        let params = Params::new(
            test_vector.mode,
            test_vector.n,
            test_vector.r,
            test_vector.p,
        )
        .unwrap();
        let actual_hash = Yescrypt::default()
            .hash_password_with_params(test_vector.password, test_vector.salt(), params)
            .unwrap();

        assert_eq!(test_vector.expected_hash, actual_hash.as_str());
    }
}

/// `yescrypt_verify()` tests
#[test]
fn verify_reference_strings() {
    let yescrypt = Yescrypt::default();

    for test_vector in MCF_TEST_VECTORS {
        let hash = PasswordHashRef::new(test_vector.expected_hash).unwrap();
        assert_eq!(yescrypt.verify_password(test_vector.password, hash), Ok(()));

        assert_eq!(
            yescrypt.verify_password(b"bogus", hash),
            Err(Error::PasswordInvalid)
        );
    }
}
