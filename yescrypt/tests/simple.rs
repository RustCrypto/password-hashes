//! Tests for encoding password hash strings in Modular Crypt Format (MCF).

#![cfg(feature = "simple")]
#![allow(non_snake_case)]

use yescrypt::{Flags, Params, yescrypt};

const YESCRYPT_P: u32 = 11;

/// First entry from yescrypt reference implementation's `TESTS-OK`.
#[test]
fn yescrypt_reference_test() {
    // Don't use this as a real password!!!
    const EXAMPLE_PASSWD: &[u8] = b"pleaseletmein";
    const EXAMPLE_SALT: &[u8] = b"WZaPV7LSUEKMo34.";
    const EXAMPLE_HASHES: &[&str] = // TODO(tarcieri): more test vectors
        &["$y$jD5.7$LdJMENpBABJJ3hIHjB1Bi.$HboGM6qPrsK.StKYGt6KErmUYtioHreJd98oIugoNB6"];

    for (i, &expected_hash) in EXAMPLE_HASHES.iter().enumerate() {
        let i = i as u32;

        // Test case logic adapted from the yescrypt C reference implementation (tests.c)
        let mut N_log2 = if i < 14 { 16 - i } else { 2 };
        let r = if i < 8 { 8 - i } else { 1 + (i & 1) };
        let mut p = if i & 1 == 1 { 1 } else { YESCRYPT_P };
        let mut flags = Flags::default();

        if (p - (i / 2)) > 1 {
            p -= i / 2;
        }

        if i & 2 != 0 {
            flags = Flags::WORM;
        } else {
            while (1 << N_log2) / p <= 3 {
                N_log2 += 1;
            }
        }

        let params = Params::new(flags, 1 << N_log2, r, p);
        let salt = &EXAMPLE_SALT[..(16 - (i as usize & 15))];

        let actual_hash = yescrypt(EXAMPLE_PASSWD, salt, &params).unwrap();
        assert_eq!(expected_hash, &actual_hash);
    }
}
