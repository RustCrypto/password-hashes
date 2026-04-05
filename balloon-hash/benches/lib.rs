#![feature(test)]

extern crate test;
use test::Bencher;

use balloon_hash::{Algorithm, Balloon, Params};
use digest::array::Array;

#[path = "../data/balloon_m_test_vectors.rs"]
mod test_vectors;
use test_vectors::{BALLOON_M_TEST_VECTORS, BalloonMTestVector};

fn bench_test_vector(b: &mut Bencher, test_vector: &BalloonMTestVector) {
    let params = Params::new(test_vector.s_cost, test_vector.t_cost, test_vector.p_cost).unwrap();
    let balloon = Balloon::<sha2::Sha256>::new(Algorithm::BalloonM, params, None);
    let mut memory = vec![Array::default(); balloon.params.s_cost.get() as usize];
    b.bytes = test_vector.password.len() as u64;
    b.iter(|| {
        let result = balloon
            .hash_password_with_memory(test_vector.password, test_vector.salt, &mut memory)
            .unwrap();
        assert_eq!(result.as_slice(), test_vector.output);
    });
}

#[bench]
fn bench_balloon_m_vector_0(b: &mut Bencher) {
    bench_test_vector(b, &BALLOON_M_TEST_VECTORS[0]);
}

#[bench]
fn bench_balloon_m_vector_1(b: &mut Bencher) {
    bench_test_vector(b, &BALLOON_M_TEST_VECTORS[1]);
}

#[bench]
fn bench_balloon_m_vector_2(b: &mut Bencher) {
    bench_test_vector(b, &BALLOON_M_TEST_VECTORS[2]);
}

#[bench]
fn bench_balloon_m_vector_3(b: &mut Bencher) {
    bench_test_vector(b, &BALLOON_M_TEST_VECTORS[3]);
}

#[bench]
fn bench_balloon_m_vector_4(b: &mut Bencher) {
    bench_test_vector(b, &BALLOON_M_TEST_VECTORS[4]);
}

#[bench]
fn bench_balloon_m_vector_5(b: &mut Bencher) {
    bench_test_vector(b, &BALLOON_M_TEST_VECTORS[5]);
}

#[bench]
fn bench_balloon_m_vector_6(b: &mut Bencher) {
    bench_test_vector(b, &BALLOON_M_TEST_VECTORS[6]);
}

#[bench]
fn bench_balloon_m_vector_7(b: &mut Bencher) {
    bench_test_vector(b, &BALLOON_M_TEST_VECTORS[7]);
}
