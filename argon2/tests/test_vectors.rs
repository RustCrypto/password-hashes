//! Argon2 test vectors.
//!
//! Taken from `draft-irtf-cfrg-argon2-12` Section 5:
//! <https://datatracker.ietf.org/doc/draft-irtf-cfrg-argon2/>

use argon2::{Argon2_Context, Argon2_type, Argon2_version};
use hex_literal::hex;

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
fn argon2d_v19() {
    let version = Argon2_version::ARGON2_VERSION_13;
    let m_cost = 32;
    let t_cost = 3;
    let parallelism = 4;
    let password = [0x01; 32];
    let salt = [0x02; 16];
    let secret = [0x03; 8];
    let ad = [0x04; 12];
    let expected_tag = hex!("512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb");

    let ctx = Argon2_Context::new(Some(&secret), t_cost, m_cost, parallelism, version).unwrap();

    let mut out = [0u8; 32];
    ctx.perform(Argon2_type::Argon2_d, &password, &salt, &ad, &mut out)
        .unwrap();

    assert_eq!(out, expected_tag);
}
