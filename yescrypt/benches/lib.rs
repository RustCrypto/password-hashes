#![no_std]
#![feature(test)]

extern crate test;

use test::Bencher;
use yescrypt::{CustomizedPasswordHasher, Params, Yescrypt, yescrypt};

#[path = "../data/test_vectors.rs"]
mod test_vectors;
use test_vectors::{TEST_VECTORS, TestVector};

#[path = "../data/mcf_test_vectors.rs"]
mod mcf_test_vectors;
use mcf_test_vectors::{MCF_TEST_VECTORS, McfTestVector};

fn bench_test_vector(bh: &mut Bencher, test_vector: &TestVector) {
    let params = test_vector.params();
    let mut buf = [0u8; 64];

    bh.bytes = test_vector.password.len() as u64;
    bh.iter(|| {
        yescrypt(
            test_vector.password,
            test_vector.salt,
            &params,
            &mut buf[..test_vector.output.len()],
        )
        .unwrap();
        // assert_eq!(test_vector.output, &buf[..test_vector.output.len()]);
    });
}

fn bench_hash_mcf(bh: &mut Bencher, test_vector: &McfTestVector) {
    let params = Params::new(
        test_vector.mode,
        test_vector.n,
        test_vector.r,
        test_vector.p,
    )
    .unwrap();
    let salt = test_vector.salt();

    bh.bytes = test_vector.password.len() as u64;
    bh.iter(|| {
        let hash = Yescrypt::default()
            .hash_password_with_params(test_vector.password, salt, params)
            .unwrap();
        // assert_eq!(test_vector.expected_hash, hash.as_str());
    });
}

#[bench]
pub fn yescrypt_kat_0(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[0]);
}

#[bench]
pub fn yescrypt_kat_1(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[1]);
}

#[bench]
pub fn yescrypt_kat_2(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[2]);
}

#[bench]
pub fn yescrypt_kat_3(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[3]);
}

#[bench]
pub fn yescrypt_kat_4(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[4]);
}

#[bench]
pub fn yescrypt_kat_5(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[5]);
}

#[bench]
pub fn yescrypt_kat_6(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[6]);
}

#[bench]
pub fn yescrypt_kat_7(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[7]);
}

#[bench]
pub fn yescrypt_kat_8(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[8]);
}

#[bench]
pub fn yescrypt_kat_9(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[9]);
}

#[bench]
pub fn yescrypt_kat_10(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[10]);
}

#[bench]
pub fn yescrypt_kat_11(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[11]);
}

#[bench]
pub fn yescrypt_kat_12(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[12]);
}

#[bench]
pub fn yescrypt_kat_13(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[13]);
}

#[bench]
pub fn yescrypt_kat_14(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[14]);
}

#[bench]
pub fn yescrypt_kat_15(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[15]);
}

#[bench]
pub fn yescrypt_kat_16(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[16]);
}

#[bench]
pub fn yescrypt_kat_17(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[17]);
}

#[bench]
pub fn yescrypt_kat_18(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[18]);
}

#[bench]
pub fn yescrypt_kat_19(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[19]);
}

#[bench]
pub fn yescrypt_kat_20(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[20]);
}

#[bench]
pub fn yescrypt_kat_21(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[21]);
}

#[bench]
pub fn yescrypt_kat_22(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[22]);
}

#[bench]
pub fn yescrypt_kat_23(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[23]);
}

#[bench]
pub fn yescrypt_kat_24(bh: &mut Bencher) {
    bench_test_vector(bh, &TEST_VECTORS[24]);
}

#[bench]
pub fn yescrypt_mcf_hash_0(bh: &mut Bencher) {
    bench_hash_mcf(bh, &MCF_TEST_VECTORS[0]);
}

#[bench]
pub fn yescrypt_mcf_hash_1(bh: &mut Bencher) {
    bench_hash_mcf(bh, &MCF_TEST_VECTORS[1]);
}

#[bench]
pub fn yescrypt_mcf_hash_2(bh: &mut Bencher) {
    bench_hash_mcf(bh, &MCF_TEST_VECTORS[2]);
}

#[bench]
pub fn yescrypt_mcf_hash_3(bh: &mut Bencher) {
    bench_hash_mcf(bh, &MCF_TEST_VECTORS[3]);
}

#[bench]
pub fn yescrypt_mcf_hash_4(bh: &mut Bencher) {
    bench_hash_mcf(bh, &MCF_TEST_VECTORS[4]);
}

#[bench]
pub fn yescrypt_mcf_hash_5(bh: &mut Bencher) {
    bench_hash_mcf(bh, &MCF_TEST_VECTORS[5]);
}

#[bench]
pub fn yescrypt_mcf_hash_6(bh: &mut Bencher) {
    bench_hash_mcf(bh, &MCF_TEST_VECTORS[6]);
}

#[bench]
pub fn yescrypt_mcf_hash_7(bh: &mut Bencher) {
    bench_hash_mcf(bh, &MCF_TEST_VECTORS[7]);
}

#[bench]
pub fn yescrypt_mcf_hash_8(bh: &mut Bencher) {
    bench_hash_mcf(bh, &MCF_TEST_VECTORS[8]);
}

#[bench]
pub fn yescrypt_mcf_hash_9(bh: &mut Bencher) {
    bench_hash_mcf(bh, &MCF_TEST_VECTORS[9]);
}

#[bench]
pub fn yescrypt_mcf_hash_10(bh: &mut Bencher) {
    bench_hash_mcf(bh, &MCF_TEST_VECTORS[10]);
}

#[bench]
pub fn yescrypt_mcf_hash_11(bh: &mut Bencher) {
    bench_hash_mcf(bh, &MCF_TEST_VECTORS[11]);
}

#[bench]
pub fn yescrypt_mcf_hash_12(bh: &mut Bencher) {
    bench_hash_mcf(bh, &MCF_TEST_VECTORS[12]);
}

#[bench]
pub fn yescrypt_mcf_hash_13(bh: &mut Bencher) {
    bench_hash_mcf(bh, &MCF_TEST_VECTORS[13]);
}

#[bench]
pub fn yescrypt_mcf_hash_14(bh: &mut Bencher) {
    bench_hash_mcf(bh, &MCF_TEST_VECTORS[14]);
}

#[bench]
pub fn yescrypt_mcf_hash_15(bh: &mut Bencher) {
    bench_hash_mcf(bh, &MCF_TEST_VECTORS[15]);
}

#[bench]
pub fn yescrypt_mcf_hash_16(bh: &mut Bencher) {
    bench_hash_mcf(bh, &MCF_TEST_VECTORS[16]);
}

#[bench]
pub fn yescrypt_mcf_hash_17(bh: &mut Bencher) {
    bench_hash_mcf(bh, &MCF_TEST_VECTORS[17]);
}
