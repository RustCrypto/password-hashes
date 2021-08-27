//! Test vectors for Argon2 password hashes in the PHC string format
//!
//! Adapted from: <https://github.com/P-H-C/phc-winner-argon2/blob/master/src/test.c>

#![cfg(all(feature = "alloc", feature = "password-hash"))]

use argon2::{Argon2, PasswordHash, PasswordVerifier};

/// Valid password
pub const VALID_PASSWORD: &[u8] = b"password";

/// Invalid password
pub const INVALID_PASSWORD: &[u8] = b"sassword";

/// Password hashes for "password"
pub const VALID_PASSWORD_HASHES: &[&str] = &[
    "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQAAAAAAAAAAA$+r0d29hqEB0yasKr55ZgICsQGSkl0v0kgwhd+U3wyRo",
    "$argon2id$v=19$m=262144,t=2,p=1$c29tZXNhbHQ$eP4eyR+zqlZX1y5xCFTkw9m5GYx0L5YWwvCFvtlbLow",
    "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
    "$argon2d$v=19$m=65536,t=2,p=1$YzI5dFpYTmhiSFFBQUFBQUFBQUFBQQ$Jxy74cswY2mq9y+u+iJcJy8EqOp4t/C7DWDzGwGB3IM"
];

#[test]
fn verifies_correct_password() {
    for hash_string in VALID_PASSWORD_HASHES {
        let hash = PasswordHash::new(hash_string).unwrap();
        assert_eq!(
            Argon2::default().verify_password(VALID_PASSWORD, &hash),
            Ok(())
        );
    }
}

#[test]
fn rejects_incorrect_password() {
    for hash_string in VALID_PASSWORD_HASHES {
        let hash = PasswordHash::new(hash_string).unwrap();
        assert!(Argon2::default()
            .verify_password(INVALID_PASSWORD, &hash)
            .is_err());
    }
}
