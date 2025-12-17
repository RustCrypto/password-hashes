//! Tests for encoding password hash strings in Modular Crypt Format (MCF).

#![cfg(feature = "password-hash")]
#![allow(non_snake_case)]

use yescrypt::{
    CustomizedPasswordHasher, Mode, Params, PasswordHashRef, PasswordVerifier, Yescrypt,
    password_hash::Error,
};

const YESCRYPT_P: u32 = 11;

// Don't use this as a real password!!!
const EXAMPLE_PASSWD: &[u8] = b"pleaseletmein";
const EXAMPLE_SALT: &[u8] = b"WZaPV7LSUEKMo34.";

/// Adapted from `TESTS-OK` in the yescrypt reference C implementation
/// https://github.com/openwall/yescrypt/blob/caa931d/TESTS-OK#L31-L66
const EXAMPLE_HASHES: &[&str] = &[
    "$y$jD5.7$LdJMENpBABJJ3hIHjB1Bi.$HboGM6qPrsK.StKYGt6KErmUYtioHreJd98oIugoNB6",
    "$y$jC4$LdJMENpBABJJ3hIHjB1B$jVg4HoqqpbmQv/NCpin.QCMagJ8o4QX7lXdzvVV0xFC", // TODO
    "$y$/B3.6$LdJMENpBABJJ3hIHjB1$h8sE4hJo.BsdlfJr0.d8bNJNPZymH7Y3kLj4aY1Rfc8",
    "$y$/A2$LdJMENpBABJJ3hIHj/$5IEld1eWdmh5lylrqHLF5dvA3ISpimEM9J1Dd05n/.3",
    "$y$j91.5$LdJMENpBABJJ3hIH$ebKnn23URD5vyLgF9cP2EvVosrUXf7UErGRV0KmC6e6",
    "$y$j80$LdJMENpBABJJ3h2$ysXVVJwuaVlI1BWoEKt/Bz3WNDDmdOWz/8KTQaHL1cC",
    "$y$/7/.4$LdJMENpBABJJ3/$lXHleh7bIZMGNtJVxGVrsIWkEIXfBedlfPui/PITflC",
    "$y$/6.$LdJMENpBABJJ$zQITmYSih5.CTY47x0IuE4wl.b3HzYGKKCSggakaQ22",
    "$y$j5..3$LdJMENpBAB3$xi27PTUNd8NsChHeLOz85JFnUOyibRHkWzprowRlR5/",
    "$y$j4/$LdJMENpBA/$tHlkpTQ8V/eEnTVau1uW36T97LIXlfPrEzdeV5SE5K7",
    "$y$/3..2$LdJMENpB$tNczXFuNUd3HMqypStCRsEaL4e4KF7ZYLBe8Hbeg0B7",
    "$y$/2/$LdJMEN3$RRorHhfsw1/P/WR6Aurg4U72e9Q7qt9vFPURdyfiqK8",
    "$y$j2..1$LdJME/$iLEt6kuTwHch6XdCxtTHfsQzYwWFmpUwgl6Ax8RH4d1",
    "$y$j0/$LdJM$k7BXzSDuoGHW56SY3HxROCiA0gWRscZe2aA0q5oHPM0",
    "$y$//..0$Ld3$6BJXezMFxaMiO5wsuoEmztvtCs/79085dZO56ADlV5B",
    "$y$///$L/$Rrrkp6OVljrIk0kcwkCDhAiHJiSthh3cKeIGHUW7Z0C",
    "$y$j1../$LdJMENpBABJJ3hIHjB1Bi.$L8OQFc8mxJPd7CpUFgkS7KqJM2I9jGXu3BdqX2D.647",
    "$y$j//$LdJMENpBABJJ3hIHjB1B$U8a2MaK.yesqWySK8Owk6PWeWmp/XuagMbpP45q1/q1",
];

/// `yescrypt()` tests
#[test]
fn compute_reference_strings() {
    for (i, &expected_hash) in EXAMPLE_HASHES.iter().enumerate() {
        let i = i as u32;

        // Test case logic adapted from the yescrypt C reference implementation (tests.c)
        let mut N_log2 = if i < 14 { 16 - i } else { 2 };
        let r = if i < 8 { 8 - i } else { 1 + (i & 1) };
        let mut p = if i & 1 == 1 { 1 } else { YESCRYPT_P };
        let mut flags = Mode::default();

        if p.saturating_sub(i / 2) > 1 {
            p -= i / 2;
        }

        if i & 2 != 0 {
            flags = Mode::Worm;
        } else {
            while (1 << N_log2) / p <= 3 {
                N_log2 += 1;
            }
        }

        let params = Params::new(flags, 1 << N_log2, r, p).unwrap();
        let salt = &EXAMPLE_SALT[..(16 - (i as usize & 15))];

        let actual_hash = Yescrypt
            .hash_password_with_params(EXAMPLE_PASSWD, salt, params)
            .unwrap();

        assert_eq!(expected_hash, actual_hash.as_str());
    }
}

/// `yescrypt_verify()` tests
#[test]
fn verify_reference_strings() {
    for &hash in EXAMPLE_HASHES {
        let hash = PasswordHashRef::new(hash).unwrap();
        assert_eq!(Yescrypt.verify_password(EXAMPLE_PASSWD, hash), Ok(()));

        assert_eq!(
            Yescrypt.verify_password(b"bogus", hash),
            Err(Error::PasswordInvalid)
        );
    }
}
