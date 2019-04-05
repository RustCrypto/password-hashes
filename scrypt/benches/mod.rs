#![no_std]
#![feature(test)]
extern crate scrypt;
extern crate test;

use test::Bencher;

#[bench]
pub fn pbkdf2_hmac_sha1_16384_20(bh: &mut Bencher) {
    let password = b"my secure password";
    let salt = b"salty salt";
    let mut buf = [0u8; 32];
    let params = scrypt::ScryptParams::new(15, 8, 1).unwrap();
    bh.iter(|| {
        scrypt::scrypt(password, salt, &params, &mut buf).unwrap();
        test::black_box(&buf);
    });
}
