#![no_std]
#![feature(test)]

extern crate test;

use test::Bencher;

#[bench]
pub fn scrypt_15_8_1(bh: &mut Bencher) {
    let password = b"my secure password";
    let salt = b"salty salt";
    let mut buf = [0u8; 32];
    let params = scrypt::Params::new(15, 8, 1).unwrap();
    bh.iter(|| {
        scrypt::scrypt(password, salt, &params, &mut buf).unwrap();
        test::black_box(&buf);
    });
}

#[bench]
pub fn scrypt_parallel_15_8_4(bh: &mut Bencher) {
    let password = b"my secure password";
    let salt = b"salty salt";
    let mut buf = [0u8; 32];
    let params = scrypt::Params::new(15, 8, 4).unwrap();
    bh.iter(|| {
        scrypt::scrypt_parallel(password, salt, &params, 4 * 1024 * 1024 * 1024, 4, &mut buf)
            .unwrap();
        test::black_box(&buf);
    });
}

#[bench]
pub fn scrypt_15_8_4(bh: &mut Bencher) {
    let password = b"my secure password";
    let salt = b"salty salt";
    let mut buf = [0u8; 32];
    let params = scrypt::Params::new(15, 8, 4).unwrap();
    bh.iter(|| {
        scrypt::scrypt_parallel(password, salt, &params, 4 * 1024 * 1024 * 1024, 1, &mut buf)
            .unwrap();
        test::black_box(&buf);
    });
}
