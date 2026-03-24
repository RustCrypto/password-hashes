#![no_std]
#![feature(test)]

extern crate test;

use sha_crypt::{Algorithm, Params, PasswordHasher, ShaCrypt};
use test::Bencher;

#[bench]
pub fn sha_crypt_sha_512(bh: &mut Bencher) {
    let input = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let salt = b"idU8Ptdv2tVGArtN";
    let rounds = 5_000;
    let sha_crypt = ShaCrypt::new(Algorithm::Sha256Crypt, Params::new(rounds).unwrap());

    bh.iter(|| {
        sha_crypt.hash_password_with_salt(input, salt).unwrap();
    });
}

#[bench]
pub fn sha_crypt_sha_256(bh: &mut Bencher) {
    let input = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let salt = b"idU8Ptdv2tVGArtN";
    let rounds = 5_000;
    let sha_crypt = ShaCrypt::new(Algorithm::Sha512Crypt, Params::new(rounds).unwrap());

    bh.iter(|| {
        sha_crypt.hash_password_with_salt(input, salt).unwrap();
    });
}
