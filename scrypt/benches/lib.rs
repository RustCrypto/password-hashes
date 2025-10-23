#![no_std]
#![feature(test)]

extern crate test;

use test::Bencher;

#[bench]
pub fn scrypt_17_8_1(bh: &mut Bencher) {
    let password = b"my secure password";
    let salt = b"salty salt";
    let mut buf = [0u8; 32];
    let params = scrypt::Params::recommended();
    bh.iter(|| {
        scrypt::scrypt(password, salt, &params, &mut buf).unwrap();
        test::black_box(&buf);
    });
}

#[bench]
pub fn scrypt_17_2_4(bh: &mut Bencher) {
    let password = b"my secure password";
    let salt = b"salty salt";
    let mut buf = [0u8; 32];
    let params = scrypt::Params::new(17, 2, 4).unwrap();
    bh.iter(|| {
        scrypt::scrypt(password, salt, &params, &mut buf).unwrap();
        test::black_box(&buf);
    });
}
