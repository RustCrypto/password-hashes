//! Tests for `password-hash` crate integration.
//!
//! PBKDF2-SHA256 vectors adapted from: https://stackoverflow.com/a/5136918

#![cfg(feature = "simple")]

use hex_literal::hex;
use pbkdf2::{Algorithm, Params, Pbkdf2, password_hash::CustomizedPasswordHasher};

const PASSWORD: &[u8] = b"passwordPASSWORDpassword";
const SALT: &[u8] = b"saltSALTsaltSALTsaltSALTsaltSALTsalt";
const EXPECTED_HASH: &str = "$pbkdf2-sha256$i=4096,\
    l=40$c2FsdFNBTFRzYWx0U0FMVHNhbHRTQUxUc2FsdFNBTFRzYWx0$NIyJ28vTKy8y2BS4EW6EzysXNH68GAAYHE4qH7jdU\
    +HGNVGMfaxH6Q";

/// Test with `algorithm: None` - uses default PBKDF2-SHA256
///
/// Input:
/// - P = "passwordPASSWORDpassword" (24 octets)
/// - S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
/// c = 4096
/// dkLen = 40
#[test]
fn hash_with_default_algorithm() {
    let params = Params {
        rounds: 4096,
        output_length: 40,
    };

    let hash = Pbkdf2
        .hash_password_customized(PASSWORD, SALT, None, None, params)
        .unwrap();

    assert_eq!(hash.algorithm, *Algorithm::Pbkdf2Sha256.ident());
    assert_eq!(hash.salt.unwrap().as_ref(), SALT);
    assert_eq!(Params::try_from(&hash).unwrap(), params);

    let expected_output = hex!(
        "34 8c 89 db cb d3 2b 2f
         32 d8 14 b8 11 6e 84 cf
         2b 17 34 7e bc 18 00 18
         1c 4e 2a 1f b8 dd 53 e1
         c6 35 51 8c 7d ac 47 e9 "
    );

    assert_eq!(hash.hash.unwrap().as_ref(), expected_output);
    assert_eq!(hash, EXPECTED_HASH.parse().unwrap());
}
