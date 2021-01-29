//! Argon2 Known Answer Tests (KAT).
//!
//! Taken from the Argon2 reference implementation as well as
//! `draft-irtf-cfrg-argon2-12` Section 5:
//! <https://datatracker.ietf.org/doc/draft-irtf-cfrg-argon2/>

// TODO(tarcieri): test full set of vectors from the reference implementation:
// https://github.com/P-H-C/phc-winner-argon2/blob/master/src/test.c

use argon2::{Algorithm, Argon2, Version};
use hex_literal::hex;

/// =======================================
/// Argon2d version number 16
/// =======================================
/// Memory: 32 KiB, Iterations: 3, Parallelism: 4 lanes, Tag length: 32 bytes
/// Password[32]:
///     01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
///     01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
/// Salt[16]: 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02
/// Secret[8]: 03 03 03 03 03 03 03 03
/// Associated data[12]: 04 04 04 04 04 04 04 04 04 04 04 04
/// Pre-hashing digest:
///     ec dc 26 dc 6b dd 21 56 19 68 97 aa 8c c9 a0 4c
///     03 ed 07 cd 12 92 67 c5 3c a6 ae f7 76 a4 30 89
///     6a 09 80 54 e4 de c3 e0 2e cd 82 c4 7f 56 2c a2
///     73 d2 f6 97 8a 5c 05 41 1a 0c d0 9d 47 7b 7b 06
/// Tag[32]:
///     96 a9 d4 e5 a1 73 40 92 c8 5e 29 f4 10 a4 59 14
///     a5 dd 1f 5c bf 08 b2 67 0d a6 8a 02 85 ab f3 2b
#[test]
fn argon2d_v0x10() {
    let version = Version::V0x10;
    let m_cost = 32;
    let t_cost = 3;
    let parallelism = 4;
    let password = [0x01; 32];
    let salt = [0x02; 16];
    let secret = [0x03; 8];
    let ad = [0x04; 12];
    let expected_tag = hex!(
        "
        96 a9 d4 e5 a1 73 40 92 c8 5e 29 f4 10 a4 59 14
        a5 dd 1f 5c bf 08 b2 67 0d a6 8a 02 85 ab f3 2b
    "
    );

    let ctx = Argon2::new(Some(&secret), t_cost, m_cost, parallelism, version).unwrap();

    let mut out = [0u8; 32];
    ctx.hash_password_into(Algorithm::Argon2d, &password, &salt, &ad, &mut out)
        .unwrap();

    assert_eq!(out, expected_tag);
}

/// =======================================
/// Argon2i version number 16
/// =======================================
/// Memory: 32 KiB, Iterations: 3, Parallelism: 4 lanes, Tag length: 32 bytes
/// Password[32]:
///     01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
///     01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
/// Salt[16]: 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02
/// Secret[8]: 03 03 03 03 03 03 03 03
/// Associated data[12]: 04 04 04 04 04 04 04 04 04 04 04 04
/// Pre-hashing digest:
///    1c dc ec c8 58 ca 1b 6d 45 c7 3c 78 d0 00 76 c5
///    ec fc 5e df 14 45 b4 43 73 97 b1 b8 20 83 ff bf
///    e3 c9 1a a8 f5 06 67 ad 8f b9 d4 e7 52 df b3 85
///    34 71 9f ba d2 22 61 33 7b 2b 55 29 81 44 09 af
/// Tag[32]:
///    87 ae ed d6 51 7a b8 30 cd 97 65 cd 82 31 ab b2
///    e6 47 a5 de e0 8f 7c 05 e0 2f cb 76 33 35 d0 fd
#[test]
fn argon2i_v0x10() {
    let version = Version::V0x10;
    let m_cost = 32;
    let t_cost = 3;
    let parallelism = 4;
    let password = [0x01; 32];
    let salt = [0x02; 16];
    let secret = [0x03; 8];
    let ad = [0x04; 12];
    let expected_tag = hex!(
        "
        87 ae ed d6 51 7a b8 30 cd 97 65 cd 82 31 ab b2
        e6 47 a5 de e0 8f 7c 05 e0 2f cb 76 33 35 d0 fd
    "
    );

    let ctx = Argon2::new(Some(&secret), t_cost, m_cost, parallelism, version).unwrap();

    let mut out = [0u8; 32];
    ctx.hash_password_into(Algorithm::Argon2i, &password, &salt, &ad, &mut out)
        .unwrap();

    assert_eq!(out, expected_tag);
}

/// =======================================
/// Argon2id version number 16
/// =======================================
/// Memory: 32 KiB, Iterations: 3, Parallelism: 4 lanes, Tag length: 32 bytes
/// Password[32]:
///     01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
///     01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
/// Salt[16]: 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02
/// Secret[8]: 03 03 03 03 03 03 03 03
/// Associated data[12]: 04 04 04 04 04 04 04 04 04 04 04 04
/// Pre-hashing digest:
///     70 65 ab 9c 82 b5 f0 e8 71 28 c7 84 7a 02 1d 1e
///     59 aa 16 66 6f c8 b4 ef ac a3 86 3f bf d6 5e 0e
///     8b a6 f6 09 eb bc 9b 60 e2 78 22 c8 24 b7 50 6f
///     b9 f9 5b e9 0e e5 84 2a ac 6e d6 b7 da 67 30 44
/// Tag[32]:
///     b6 46 15 f0 77 89 b6 6b 64 5b 67 ee 9e d3 b3 77
///     ae 35 0b 6b fc bb 0f c9 51 41 ea 8f 32 26 13 c0
#[test]
fn argon2id_v0x10() {
    let version = Version::V0x10;
    let m_cost = 32;
    let t_cost = 3;
    let parallelism = 4;
    let password = [0x01; 32];
    let salt = [0x02; 16];
    let secret = [0x03; 8];
    let ad = [0x04; 12];
    let expected_tag = hex!(
        "
        b6 46 15 f0 77 89 b6 6b 64 5b 67 ee 9e d3 b3 77
        ae 35 0b 6b fc bb 0f c9 51 41 ea 8f 32 26 13 c0
    "
    );

    let ctx = Argon2::new(Some(&secret), t_cost, m_cost, parallelism, version).unwrap();

    let mut out = [0u8; 32];
    ctx.hash_password_into(Algorithm::Argon2id, &password, &salt, &ad, &mut out)
        .unwrap();

    assert_eq!(out, expected_tag);
}

/// =======================================
/// Argon2d version number 19
/// =======================================
/// Memory: 32 KiB
/// Passes: 3
/// Parallelism: 4 lanes
/// Tag length: 32 bytes
/// Password[32]:
///     01 01 01 01 01 01 01 01
///     01 01 01 01 01 01 01 01
///     01 01 01 01 01 01 01 01
///     01 01 01 01 01 01 01 01
/// Salt[16]: 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02
/// Secret[8]: 03 03 03 03 03 03 03 03
/// Associated data[12]: 04 04 04 04 04 04 04 04 04 04 04 04
/// Pre-hashing digest:
///     b8 81 97 91 a0 35 96 60
///     bb 77 09 c8 5f a4 8f 04
///     d5 d8 2c 05 c5 f2 15 cc
///     db 88 54 91 71 7c f7 57
///     08 2c 28 b9 51 be 38 14
///     10 b5 fc 2e b7 27 40 33
///     b9 fd c7 ae 67 2b ca ac
///     5d 17 90 97 a4 af 31 09
/// Tag[32]:
///     51 2b 39 1b 6f 11 62 97
///     53 71 d3 09 19 73 42 94
///     f8 68 e3 be 39 84 f3 c1
///     a1 3a 4d b9 fa be 4a cb
#[test]
fn argon2d_v0x13() {
    let version = Version::V0x13;
    let m_cost = 32;
    let t_cost = 3;
    let parallelism = 4;
    let password = [0x01; 32];
    let salt = [0x02; 16];
    let secret = [0x03; 8];
    let ad = [0x04; 12];
    let expected_tag = hex!(
        "
        51 2b 39 1b 6f 11 62 97
        53 71 d3 09 19 73 42 94
        f8 68 e3 be 39 84 f3 c1
        a1 3a 4d b9 fa be 4a cb
        "
    );

    let ctx = Argon2::new(Some(&secret), t_cost, m_cost, parallelism, version).unwrap();

    let mut out = [0u8; 32];
    ctx.hash_password_into(Algorithm::Argon2d, &password, &salt, &ad, &mut out)
        .unwrap();

    assert_eq!(out, expected_tag);
}

/// =======================================
/// Argon2i version number 19
/// =======================================
/// Memory: 32 KiB
/// Passes: 3
/// Parallelism: 4 lanes
/// Tag length: 32 bytes
/// Password[32]:
///     01 01 01 01 01 01 01 01
///     01 01 01 01 01 01 01 01
///     01 01 01 01 01 01 01 01
///     01 01 01 01 01 01 01 01
/// Salt[16]: 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02
/// Secret[8]: 03 03 03 03 03 03 03 03
/// Associated data[12]: 04 04 04 04 04 04 04 04 04 04 04 04
/// Pre-hashing digest:
///     c4 60 65 81 52 76 a0 b3
///     e7 31 73 1c 90 2f 1f d8
///     0c f7 76 90 7f bb 7b 6a
///     5c a7 2e 7b 56 01 1f ee
///     ca 44 6c 86 dd 75 b9 46
///     9a 5e 68 79 de c4 b7 2d
///     08 63 fb 93 9b 98 2e 5f
///     39 7c c7 d1 64 fd da a9
/// Tag[32]:
///     c8 14 d9 d1 dc 7f 37 aa
///     13 f0 d7 7f 24 94 bd a1
///     c8 de 6b 01 6d d3 88 d2
///     99 52 a4 c4 67 2b 6c e8
#[test]
fn argon2i_v0x13() {
    let version = Version::V0x13;
    let m_cost = 32;
    let t_cost = 3;
    let parallelism = 4;
    let password = [0x01; 32];
    let salt = [0x02; 16];
    let secret = [0x03; 8];
    let ad = [0x04; 12];
    let expected_tag = hex!(
        "
        c8 14 d9 d1 dc 7f 37 aa
        13 f0 d7 7f 24 94 bd a1
        c8 de 6b 01 6d d3 88 d2
        99 52 a4 c4 67 2b 6c e8
    "
    );

    let ctx = Argon2::new(Some(&secret), t_cost, m_cost, parallelism, version).unwrap();

    let mut out = [0u8; 32];
    ctx.hash_password_into(Algorithm::Argon2i, &password, &salt, &ad, &mut out)
        .unwrap();

    assert_eq!(out, expected_tag);
}

/// =======================================
/// Argon2id version number 19
/// =======================================
/// Memory: 32 KiB, Passes: 3,
/// Parallelism: 4 lanes, Tag length: 32 bytes
/// Password[32]:
///     01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
///     01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
/// Salt[16]: 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02
/// Secret[8]: 03 03 03 03 03 03 03 03
/// Associated data[12]: 04 04 04 04 04 04 04 04 04 04 04 04
/// Pre-hashing digest:
///     28 89 de 48 7e b4 2a e5 00 c0 00 7e d9 25 2f 10
///     69 ea de c4 0d 57 65 b4 85 de 6d c2 43 7a 67 b8
///     54 6a 2f 0a cc 1a 08 82 db 8f cf 74 71 4b 47 2e
///     94 df 42 1a 5d a1 11 2f fa 11 43 43 70 a1 e9 97
/// Tag[32]:
///     0d 64 0d f5 8d 78 76 6c 08 c0 37 a3 4a 8b 53 c9
///     d0 1e f0 45 2d 75 b6 5e b5 25 20 e9 6b 01 e6 59
#[test]
fn argon2id_v0x13() {
    let version = Version::V0x13;
    let m_cost = 32;
    let t_cost = 3;
    let parallelism = 4;
    let password = [0x01; 32];
    let salt = [0x02; 16];
    let secret = [0x03; 8];
    let ad = [0x04; 12];
    let expected_tag = hex!(
        "
        0d 64 0d f5 8d 78 76 6c 08 c0 37 a3 4a 8b 53 c9
        d0 1e f0 45 2d 75 b6 5e b5 25 20 e9 6b 01 e6 59
    "
    );

    let ctx = Argon2::new(Some(&secret), t_cost, m_cost, parallelism, version).unwrap();

    let mut out = [0u8; 32];
    ctx.hash_password_into(Algorithm::Argon2id, &password, &salt, &ad, &mut out)
        .unwrap();

    assert_eq!(out, expected_tag);
}
