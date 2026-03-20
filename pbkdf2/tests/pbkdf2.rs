#![cfg(feature = "hmac")]

use belt_hash::BeltHash;
use hex_literal::hex;
#[cfg(all(feature = "sha2", feature = "phc"))]
use pbkdf2::{
    Params, Pbkdf2,
    password_hash::{PasswordHasher, PasswordVerifier},
};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use streebog::Streebog512;

macro_rules! test {
    (
        $hash:ty;
        $($password:expr, $salt:expr, $rounds:expr, $($expected_hash:literal)*;)*
    ) => {
        $({
            const EXPECTED_HASH: &[u8] = &hex_literal::hex!($($expected_hash)*);
            const N: usize = EXPECTED_HASH.len();

            let hash = pbkdf2::pbkdf2_hmac_array::<$hash, N>($password, $salt, $rounds);
            assert_eq!(hash[..], EXPECTED_HASH[..]);
        })*
    };
}

/// Test vectors from RFC 6070:
/// https://www.rfc-editor.org/rfc/rfc6070
#[test]
fn pbkdf2_rfc6070() {
    test!(
        Sha1;
        b"password", b"salt", 1, "0c60c80f961f0e71f3a9b524af6012062fe037a6";
        b"password", b"salt", 2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957";
        b"password", b"salt", 4096, "4b007901b765489abead49d926f721d065a429c1";
        // this test passes, but takes a long time to execute
        // b"password", b"salt", 16777216, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984";
        b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096,
            "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038";
        b"pass\0word", b"sa\0lt", 4096, "56fa6aa75548099dcc37d7f03425e0c3";
    );
}

/// Test vectors from R 50.1.111-2016:
/// https://tc26.ru/standard/rs/Р%2050.1.111-2016.pdf
#[test]
fn pbkdf2_streebog() {
    test!(
        Streebog512;
        b"password", b"salt", 1,
            "64770af7f748c3b1c9ac831dbcfd85c2"
            "6111b30a8a657ddc3056b80ca73e040d"
            "2854fd36811f6d825cc4ab66ec0a68a4"
            "90a9e5cf5156b3a2b7eecddbf9a16b47";
        b"password", b"salt", 2,
            "5a585bafdfbb6e8830d6d68aa3b43ac0"
            "0d2e4aebce01c9b31c2caed56f0236d4"
            "d34b2b8fbd2c4e89d54d46f50e47d45b"
            "bac301571743119e8d3c42ba66d348de";
        b"password", b"salt", 4096,
            "e52deb9a2d2aaff4e2ac9d47a41f34c2"
            "0376591c67807f0477e32549dc341bc7"
            "867c09841b6d58e29d0347c996301d55"
            "df0d34e47cf68f4e3c2cdaf1d9ab86c3";
        // this test passes, but takes a long time to execute
        // b"password", b"salt", 16777216,
        //     "49e4843bba76e300afe24c4d23dc7392"
        //     "def12f2c0e244172367cd70a8982ac36"
        //     "1adb601c7e2a314e8cb7b1e9df840e36"
        //     "ab5615be5d742b6cf203fb55fdc48071";
        b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096,
            "b2d8f1245fc4d29274802057e4b54e0a"
            "0753aa22fc53760b301cf008679e58fe"
            "4bee9addcae99ba2b0b20f431a9c5e50"
            "f395c89387d0945aedeca6eb4015dfc2"
            "bd2421ee9bb71183ba882ceebfef259f"
            "33f9e27dc6178cb89dc37428cf9cc52a"
            "2baa2d3a";
        b"pass\0word", b"sa\0lt", 4096,
            "50df062885b69801a3c10248eb0a27ab"
            "6e522ffeb20c991c660f001475d73a4e"
            "167f782c18e97e92976d9c1d970831ea"
            "78ccb879f67068cdac1910740844e830";
    );
}

/// Test vector from STB 4.101.45-2013 (page 33):
/// https://apmi.bsu.by/assets/files/std/bign-spec294.pdf
#[test]
fn pbkdf2_belt() {
    test!(
        BeltHash;
        &hex!("42313934 42414338 30413038 46353342"),
        &hex!("BE329713 43FC9A48"),
        10_000,
        "3D331BBB B1FBBB40 E4BF22F6 CB9A689E F13A77DC 09ECF932 91BFE424 39A72E7D";
    );
}
#[test]
fn pbkdf2_algorithm_defaults_use_matching_rounds_sha_256() {
    test!(
        Sha256;
        b"password", b"salt", 1, "120fb6cffcf8b32c43e7225256c4f837a86548c9";
        b"password", b"salt", 2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8e";
        b"password", b"salt", 4096, "c5e478d59288c841aa530db6845c4c8d962893a0";
        // this test passes, but takes a long time to execute
        // b"password", b"salt", 16777216, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984";
        b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096,
            "348c89dbcbd32b2f32d814b8116e84cf2b17347e";
        b"pass\0word", b"sa\0lt", 600_000, "efc5286bfbd0681c9600b5c024b8ba1b5ae0f0ab";
    );
}

#[test]
fn pbkdf2_algorithm_defaults_use_matching_rounds_sha_512() {
    test!(
        Sha512;
        b"password", b"salt", 1, "867f70cf1ade02cff3752599a3a53dc4af34c7a6";
        b"password", b"salt", 2, "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e";
        b"password", b"salt", 4096, "d197b1b33db0143e018b12f3d1d1479e6cdebdcc";
        // this test passes, but takes a long time to execute
        // b"password", b"salt", 16777216, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984";
        b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096,
            "8c0511f4c6e597c6ac6315d8f0362e225f3c5014";
        b"pass\0word", b"sa\0lt", 210_000, "4941abc239d618e79f63d3d300e5f81954164bc1";
    );
}

#[test]
#[cfg(all(feature = "sha2", feature = "phc"))]
fn pbkdf2_sha_512_default_iterations() {
    let hash = Pbkdf2::SHA512
        .hash_password_with_salt(b"pass\0word", b"testsalt")
        .unwrap();
    assert_eq!(Params::try_from(&hash).unwrap().rounds(), 210_000);
}

#[test]
#[cfg(all(feature = "sha2", feature = "phc"))]
fn pbkdf2_sha_256_default_iterations() {
    let hash = Pbkdf2::SHA256
        .hash_password_with_salt(b"pass\0word", b"testsalt")
        .unwrap();
    assert_eq!(Params::try_from(&hash).unwrap().rounds(), 600_000);
}
