//! `Hashing`: a hash computed a slice at a time.

#![cfg(feature = "alloc")]
#![allow(clippy::unwrap_used, reason = "tests")]

use argon2::{Algorithm, Argon2, Block, Error, Params, Version};

const LANES: u32 = 4;
const PASSES: u32 = 2;

fn argon2(algorithm: Algorithm) -> Argon2<'static> {
    Argon2::new(
        algorithm,
        Version::V0x13,
        Params::new(256, PASSES, LANES, Some(32)).unwrap(),
    )
}

fn expected(argon2: &Argon2<'_>) -> [u8; 32] {
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(b"password", b"somesalt", &mut out)
        .unwrap();
    out
}

#[test]
fn one_lane_at_a_time() {
    for algorithm in [Algorithm::Argon2d, Algorithm::Argon2i, Algorithm::Argon2id] {
        let argon2 = argon2(algorithm);
        let mut blocks = vec![Block::new(); argon2.params().block_count()];
        let mut out = [0u8; 32];
        let mut hashing = argon2
            .start_hash_password_into(b"password", b"somesalt", &mut out, &mut blocks)
            .unwrap();
        let mut computed = 0;
        while let Some(segments) = hashing.next_segments() {
            // The same segments are given out again until they are all done.
            assert!(segments.work_one());
            computed += 1;
        }
        assert_eq!(computed, PASSES * 4 * LANES);
        assert!(hashing.next_segments().is_none());
        assert_eq!(out, expected(&argon2));
    }
}

#[test]
fn threads() {
    let argon2 = argon2(Algorithm::Argon2id);
    let mut blocks = vec![Block::new(); argon2.params().block_count()];
    let mut out = [0u8; 32];
    let mut hashing = argon2
        .start_hash_password_into(b"password", b"somesalt", &mut out, &mut blocks)
        .unwrap();
    while let Some(segments) = hashing.next_segments() {
        std::thread::scope(|s| {
            for _ in 1..segments.lanes() {
                s.spawn(|| segments.work());
            }
            segments.work();
        });
    }
    assert_eq!(out, expected(&argon2));
}

#[test]
fn lanes_left_given_out_again() {
    let argon2 = argon2(Algorithm::Argon2id);
    let mut blocks = vec![Block::new(); argon2.params().block_count()];
    let mut out = [0u8; 32];
    let mut hashing = argon2
        .start_hash_password_into(b"password", b"somesalt", &mut out, &mut blocks)
        .unwrap();
    // A lane, then the rest on threads.
    hashing.next_segments().unwrap().work_one();
    while let Some(segments) = hashing.next_segments() {
        std::thread::scope(|s| {
            s.spawn(|| segments.work());
            segments.work();
        });
    }
    assert_eq!(out, expected(&argon2));
}

/// Hours of work (2³² − 1 passes), stopped after 3 slices: dropping the `Hashing` stops the hash,
/// and `out` isn't written.
#[test]
fn stopped() {
    let params = Params::new(Params::MIN_M_COST, Params::MAX_T_COST, 1, Some(32)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut blocks = vec![Block::new(); argon2.params().block_count()];
    let mut out = [0u8; 32];
    let mut hashing = argon2
        .start_hash_password_into(b"password", b"somesalt", &mut out, &mut blocks)
        .unwrap();
    for _ in 0..3 {
        hashing.next_segments().unwrap().work();
    }
    // `hashing` is no longer used: the hash stops here.
    assert_eq!(out, [0u8; 32]);
}

#[test]
fn output_checked_at_start() {
    let argon2 = argon2(Algorithm::Argon2id);
    let mut blocks = vec![Block::new(); argon2.params().block_count()];
    let mut out = [0u8; 16];
    let result = argon2.start_hash_password_into(b"password", b"somesalt", &mut out, &mut blocks);
    assert_eq!(result.unwrap_err(), Error::OutputTooShort);
}
