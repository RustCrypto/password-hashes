#![no_std]
#![feature(test)]

extern crate test;

use hmac::Hmac;
use pbkdf2::pbkdf2;
use test::Bencher;

#[bench]
pub fn pbkdf2_hmac_sha256_16384_20(bh: &mut Bencher) {
    let password = b"my secure password";
    let salt = b"salty salt";
    let mut buf = [0u8; 20];
    bh.iter(|| {
        pbkdf2::<Hmac<sha2::Sha256>>(password, salt, 16_384, &mut buf).unwrap();
        test::black_box(&buf);
    });
}

/// Benchmark PBKDF2-HMAC-SHA256 with 600,000 rounds. This is the recommended configuration for PBKDF2-HMAC-SHA256 according to the OWASP cheat sheet:
/// <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2>
#[bench]
pub fn pbkdf2_hmac_sha256_600000_20(bh: &mut Bencher) {
    let password = b"my secure password";
    let salt = b"salty salt";
    let mut buf = [0u8; 20];
    bh.iter(|| {
        pbkdf2::<Hmac<sha2::Sha256>>(password, salt, 600_000, &mut buf).unwrap();
        test::black_box(&buf);
    });
}

#[bench]
pub fn pbkdf2_hmac_sha512_16384_20(bh: &mut Bencher) {
    let password = b"my secure password";
    let salt = b"salty salt";
    let mut buf = [0u8; 20];
    bh.iter(|| {
        pbkdf2::<Hmac<sha2::Sha512>>(password, salt, 16_384, &mut buf).unwrap();
        test::black_box(&buf);
    });
}

/// Benchmark PBKDF2-HMAC-SHA512 with 210,000 rounds. This is the recommended configuration for PBKDF2-HMAC-SHA512 according to the OWASP cheat sheet:
/// <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2>
#[bench]
pub fn pbkdf2_hmac_sha512_210000_20(bh: &mut Bencher) {
    let password = b"my secure password";
    let salt = b"salty salt";
    let mut buf = [0u8; 20];
    bh.iter(|| {
        pbkdf2::<Hmac<sha2::Sha512>>(password, salt, 210_000, &mut buf).unwrap();
        test::black_box(&buf);
    });
}
