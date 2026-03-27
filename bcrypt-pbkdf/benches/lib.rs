#![feature(test)]

extern crate test;

use bcrypt_pbkdf::bcrypt_pbkdf_with_memory;
use test::Bencher;

#[path = "../data/test_vectors.rs"]
mod test_vectors;
use test_vectors::{TEST_VECTORS, Test};

fn bench_test_vector(b: &mut Bencher, test_vector: &Test) {
    let mut out = vec![0; test_vector.out.len()];
    let len = test_vector.out.len().div_ceil(32) * 32;
    let mut memory = vec![0; len];

    b.bytes = test_vector.password.len() as u64;
    b.iter(|| {
        bcrypt_pbkdf_with_memory(
            test_vector.password,
            test_vector.salt,
            test_vector.rounds,
            &mut out,
            &mut memory,
        )
        .unwrap();

        assert_eq!(out, test_vector.out);
    });
}

#[bench]
fn bench_vector_0(b: &mut Bencher) {
    bench_test_vector(b, &TEST_VECTORS[0]);
}

#[bench]
fn bench_vector_1(b: &mut Bencher) {
    bench_test_vector(b, &TEST_VECTORS[1]);
}

#[bench]
fn bench_vector_2(b: &mut Bencher) {
    bench_test_vector(b, &TEST_VECTORS[2]);
}

#[bench]
fn bench_vector_3(b: &mut Bencher) {
    bench_test_vector(b, &TEST_VECTORS[3]);
}

#[bench]
fn bench_vector_4(b: &mut Bencher) {
    bench_test_vector(b, &TEST_VECTORS[4]);
}

#[bench]
fn bench_vector_5(b: &mut Bencher) {
    bench_test_vector(b, &TEST_VECTORS[5]);
}

#[bench]
fn bench_vector_6(b: &mut Bencher) {
    bench_test_vector(b, &TEST_VECTORS[6]);
}

#[bench]
fn bench_vector_7(b: &mut Bencher) {
    bench_test_vector(b, &TEST_VECTORS[7]);
}

#[bench]
fn bench_vector_8(b: &mut Bencher) {
    bench_test_vector(b, &TEST_VECTORS[8]);
}
