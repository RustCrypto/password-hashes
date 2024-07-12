//! Adapted from the reference implementation's `TESTS-OK`.
//! <https://github.com/openwall/yescrypt/blob/e5873f8/TESTS-OK>

use hex_literal::hex;
use std::{mem, ptr};
use yescrypt::{yescrypt_init_local, yescrypt_kdf, Flags, Local, Params};

// Test function whose parameters match the upstream KATs
fn yescrypt(
    passwd: &[u8],
    salt: &[u8],
    flags: Flags,
    n: u64,
    r: u32,
    p: u32,
    t: u32,
    g: u32,
    dstlen: usize,
) -> Vec<u8> {
    let params = Params {
        flags,
        N: n,
        r,
        p,
        t,
        g,
        NROM: 0,
    };

    let mut local: Local = unsafe { mem::zeroed() };
    unsafe {
        yescrypt_init_local(&mut local);
    }

    let mut dst = vec![0u8; dstlen];

    unsafe {
        yescrypt_kdf(
            ptr::null(),
            &mut local,
            passwd.as_ptr(),
            passwd.len(),
            salt.as_ptr(),
            salt.len(),
            &params,
            dst.as_mut_ptr(),
            dstlen,
        )
    };
    dst
}

// yescrypt("", "", 0, 16, 1, 1, 0, 0) = 77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97 f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42 fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17 e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06
#[test]
fn kat0() {
    const EXPECTED: [u8; 64] = hex!("77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97 f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42 fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17 e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06");
    let actual = yescrypt(b"", b"", 0, 16, 1, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("", "", 0, 16, 1, 1, 0, 0) = 77 d6 57 62 38 65 7b 20
#[test]
fn kat1() {
    const EXPECTED: [u8; 8] = hex!("77 d6 57 62 38 65 7b 20");
    let actual = yescrypt(b"", b"", 0, 16, 1, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("", "", 0, 4, 1, 1, 0, 0) = ef ad 0c 23 31 4c b5 72 bc 3c fb 15 43 da 42 f8 a8 b0 73 00 4c 86 6b 64 ab 50 55 a4 f0 9f a5 f5 71 14 2e bf e7 e0 5a 3b 92 c4 32 f3 1d ea 95 ad 5f 9c 85 4b 64 56 46 2f 4b d0 f7 32 b7 cd c5 49
#[test]
fn kat2() {
    const EXPECTED: [u8; 64] = hex!("ef ad 0c 23 31 4c b5 72 bc 3c fb 15 43 da 42 f8 a8 b0 73 00 4c 86 6b 64 ab 50 55 a4 f0 9f a5 f5 71 14 2e bf e7 e0 5a 3b 92 c4 32 f3 1d ea 95 ad 5f 9c 85 4b 64 56 46 2f 4b d0 f7 32 b7 cd c5 49");
    let actual = yescrypt(b"", b"", 0, 4, 1, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("", "", 1, 4, 1, 1, 0, 0) = 85 dd a4 8c 9e c9 de 2f 7f 1a e8 b4 df ed a5 1f 8b 6d 56 f3 08 1b e1 a7 c0 83 3b a2 71 9a 36 ab 02 88 5d ae 36 55 7d 34 26 86 b1 7b a7 5f 2c 21 77 92 de 09 70 ab 1d 07 a9 c7 50 93 6d 31 42 6f
#[test]
fn kat3() {
    const EXPECTED: [u8; 64] = hex!("85 dd a4 8c 9e c9 de 2f 7f 1a e8 b4 df ed a5 1f 8b 6d 56 f3 08 1b e1 a7 c0 83 3b a2 71 9a 36 ab 02 88 5d ae 36 55 7d 34 26 86 b1 7b a7 5f 2c 21 77 92 de 09 70 ab 1d 07 a9 c7 50 93 6d 31 42 6f");
    let actual = yescrypt(b"", b"", 1, 4, 1, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("", "", 1, 4, 1, 1, 0, 0) = 85 dd a4 8c 9e c9 de 2f
#[test]
fn kat4() {
    const EXPECTED: [u8; 8] = hex!("85 dd a4 8c 9e c9 de 2f");
    let actual = yescrypt(b"", b"", 1, 4, 1, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("", "", 1, 4, 1, 1, 1, 0) = 4b aa 8c d8 60 8b a9 1f 3e 34 39 d9 ec 4f ae 8f 9f c0 92 d9 ca 22 b7 37 7e 31 ae 5b 9a d7 87 7c 11 68 69 11 62 dd 0e 5e f0 49 e5 70 65 0c be d4 38 4a d6 05 34 fb 0c be d1 9f f3 f0 33 c9 4b 0c
#[test]
fn kat5() {
    const EXPECTED: [u8; 64] = hex!("4b aa 8c d8 60 8b a9 1f 3e 34 39 d9 ec 4f ae 8f 9f c0 92 d9 ca 22 b7 37 7e 31 ae 5b 9a d7 87 7c 11 68 69 11 62 dd 0e 5e f0 49 e5 70 65 0c be d4 38 4a d6 05 34 fb 0c be d1 9f f3 f0 33 c9 4b 0c");
    let actual = yescrypt(b"", b"", 1, 4, 1, 1, 1, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("", "", 1, 4, 1, 1, 2, 0) = e6 e8 bb a0 9b 64 12 ff b0 b3 cc 35 e3 7d 0b 78 2a 47 fb aa dc 57 a0 76 d7 c6 cc 2e 70 91 9a 1b 8d 47 38 c4 f8 33 55 69 07 42 d9 be d7 1c 3b 8f b0 d7 eb 08 6a b1 34 c5 e5 57 07 c2 c1 3c 75 ef
#[test]
fn kat6() {
    const EXPECTED: [u8; 64] = hex!("e6 e8 bb a0 9b 64 12 ff b0 b3 cc 35 e3 7d 0b 78 2a 47 fb aa dc 57 a0 76 d7 c6 cc 2e 70 91 9a 1b 8d 47 38 c4 f8 33 55 69 07 42 d9 be d7 1c 3b 8f b0 d7 eb 08 6a b1 34 c5 e5 57 07 c2 c1 3c 75 ef");
    let actual = yescrypt(b"", b"", 1, 4, 1, 1, 2, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("", "", 1, 4, 1, 1, 3, 0) = ac d9 a4 20 1c f4 a4 76 ec f7 ba a6 11 3d 86 fb 65 cd 07 10 2b 40 04 e4 f9 d9 9c d3 42 55 a1 08 99 7d 70 ae 0a 64 bf 0a 4d 96 c1 73 ab f8 82 79 c1 a9 4a d9 bd f1 68 ed fb bd 90 f6 6e d5 c8 0d
#[test]
fn kat7() {
    const EXPECTED: [u8; 64] = hex!("ac d9 a4 20 1c f4 a4 76 ec f7 ba a6 11 3d 86 fb 65 cd 07 10 2b 40 04 e4 f9 d9 9c d3 42 55 a1 08 99 7d 70 ae 0a 64 bf 0a 4d 96 c1 73 ab f8 82 79 c1 a9 4a d9 bd f1 68 ed fb bd 90 f6 6e d5 c8 0d");
    let actual = yescrypt(b"", b"", 1, 4, 1, 1, 3, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("", "", 1, 4, 1, 1, 3, 0) = ac d9 a4 20 1c f4 a4 76 ec f7 ba a6 11 3d 86 fb 65 cd 07 10 2b 40 04 e4 f9 d9 9c d3 42 55 a1 08 99
#[test]
fn kat8() {
    const EXPECTED: [u8; 33] = hex!("ac d9 a4 20 1c f4 a4 76 ec f7 ba a6 11 3d 86 fb 65 cd 07 10 2b 40 04 e4 f9 d9 9c d3 42 55 a1 08 99");
    let actual = yescrypt(b"", b"", 1, 4, 1, 1, 3, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("", "", 1, 4, 1, 1, 3, 0) = ac d9 a4 20 1c f4 a4 76 ec f7 ba a6 11 3d 86 fb 65 cd 07 10 2b 40 04 e4 f9 d9 9c d3 42 55 a1 08
#[test]
fn kat9() {
    const EXPECTED: [u8; 32] = hex!("ac d9 a4 20 1c f4 a4 76 ec f7 ba a6 11 3d 86 fb 65 cd 07 10 2b 40 04 e4 f9 d9 9c d3 42 55 a1 08");
    let actual = yescrypt(b"", b"", 1, 4, 1, 1, 3, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("", "", 1, 4, 1, 1, 3, 0) = ac d9 a4 20 1c f4 a4 76 ec f7 ba a6 11 3d 86 fb 65 cd 07 10 2b 40 04 e4 f9 d9 9c d3 42 55 a1
#[test]
fn kat10() {
    const EXPECTED: [u8; 31] = hex!("ac d9 a4 20 1c f4 a4 76 ec f7 ba a6 11 3d 86 fb 65 cd 07 10 2b 40 04 e4 f9 d9 9c d3 42 55 a1");
    let actual = yescrypt(b"", b"", 1, 4, 1, 1, 3, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("", "", 1, 4, 1, 1, 3, 0) = ac
#[test]
fn kat11() {
    const EXPECTED: [u8; 1] = hex!("ac");
    let actual = yescrypt(b"", b"", 1, 4, 1, 1, 3, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("", "", 182, 4, 1, 1, 0, 0) = 0c d5 af 76 eb 24 1d f8 11 9a 9a 12 2a e3 69 20 bc c7 f4 14 b9 c0 d5 8f 45 00 80 60 da de 46 b0 c8 09 22 bd cc 16 a3 ab 5d 20 1d 4c 61 40 c6 71 be 1f 75 27 2c a9 04 73 9d 5a d1 ff 67 2b 0c 21
#[test]
fn kat12() {
    const EXPECTED: [u8; 64] = hex!("0c d5 af 76 eb 24 1d f8 11 9a 9a 12 2a e3 69 20 bc c7 f4 14 b9 c0 d5 8f 45 00 80 60 da de 46 b0 c8 09 22 bd cc 16 a3 ab 5d 20 1d 4c 61 40 c6 71 be 1f 75 27 2c a9 04 73 9d 5a d1 ff 67 2b 0c 21");
    let actual = yescrypt(b"", b"", 182, 4, 1, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("", "", 182, 4, 1, 1, 0, 0) = 0c d5 af 76
#[test]
fn kat13() {
    const EXPECTED: [u8; 4] = hex!("0c d5 af 76");
    let actual = yescrypt(b"", b"", 182, 4, 1, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("", "", 182, 4, 1, 1, 1, 0) = 23 b6 ad f0 b6 0c 9a 99 7f 58 58 3d 80 cd a4 8c 63 8c dc 2f 28 9e df 93 a7 08 07 72 5a 0d 35 c4 68 ca 36 2c 55 57 cc 04 b6 81 1e 2e 73 08 41 f5 26 d8 f4 f7 ac fb fa 9e 06 fe 1f 38 3a 71 15 5e
#[test]
fn kat14() {
    const EXPECTED: [u8; 64] = hex!("23 b6 ad f0 b6 0c 9a 99 7f 58 58 3d 80 cd a4 8c 63 8c dc 2f 28 9e df 93 a7 08 07 72 5a 0d 35 c4 68 ca 36 2c 55 57 cc 04 b6 81 1e 2e 73 08 41 f5 26 d8 f4 f7 ac fb fa 9e 06 fe 1f 38 3a 71 15 5e");
    let actual = yescrypt(b"", b"", 182, 4, 1, 1, 1, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("", "", 182, 4, 1, 1, 1, 0) = 23 b6 ad f0 b6 0c 9a 99 7f 58 58 3d 80 cd a4 8c 63 8c dc 2f 28 9e df 93 a7 08 07 72 5a 0d 35 c4 68
#[test]
fn kat15() {
    const EXPECTED: [u8; 33] = hex!("23 b6 ad f0 b6 0c 9a 99 7f 58 58 3d 80 cd a4 8c 63 8c dc 2f 28 9e df 93 a7 08 07 72 5a 0d 35 c4 68");
    let actual = yescrypt(b"", b"", 182, 4, 1, 1, 1, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("", "", 182, 4, 1, 1, 1, 0) = 23 b6 ad f0 b6 0c 9a 99 7f 58 58 3d 80 cd a4 8c 63 8c dc 2f 28 9e df 93 a7 08 07 72 5a 0d 35 c4
#[test]
fn kat16() {
    const EXPECTED: [u8; 32] = hex!("23 b6 ad f0 b6 0c 9a 99 7f 58 58 3d 80 cd a4 8c 63 8c dc 2f 28 9e df 93 a7 08 07 72 5a 0d 35 c4");
    let actual = yescrypt(b"", b"", 182, 4, 1, 1, 1, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("", "", 182, 4, 1, 1, 1, 0) = 23 b6 ad f0 b6 0c 9a 99 7f 58 58 3d 80 cd a4 8c 63 8c dc 2f 28 9e df 93 a7 08 07 72 5a 0d 35
#[test]
fn kat17() {
    const EXPECTED: [u8; 31] = hex!("23 b6 ad f0 b6 0c 9a 99 7f 58 58 3d 80 cd a4 8c 63 8c dc 2f 28 9e df 93 a7 08 07 72 5a 0d 35");
    let actual = yescrypt(b"", b"", 182, 4, 1, 1, 1, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("", "", 182, 4, 1, 1, 1, 0) = 23
#[test]
fn kat18() {
    const EXPECTED: [u8; 1] = hex!("23");
    let actual = yescrypt(b"", b"", 182, 4, 1, 1, 1, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("p", "s", 182, 16, 8, 1, 10, 0) = e1 f9 81 73 3a 94 05 2f cd 7a cb 14 05 df 0b bd e8 e4 99 b6 a1 33 1b 77 59 09 b4 8c 2f 51 6c 40 dc c8 30 16 35 b7 23 7b
#[test]
fn kat19() {
    const EXPECTED: [u8; 40] = hex!("e1 f9 81 73 3a 94 05 2f cd 7a cb 14 05 df 0b bd e8 e4 99 b6 a1 33 1b 77 59 09 b4 8c 2f 51 6c 40 dc c8 30 16 35 b7 23 7b");
    let actual = yescrypt(b"p", b"s", 182, 16, 8, 1, 10, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("p", "s", 1, 16, 8, 1, 10, 0) = 9e 7a 40 97 64 42 84 cf 3b 73 b6 04 50 ff 23 0c dc b6 b1 b1 9b 15 09 ee b4 82 f6 96 c4 f1 c7 05 c0 0f 74 02 16 18 3a 12
#[test]
fn kat20() {
    const EXPECTED: [u8; 40] = hex!("9e 7a 40 97 64 42 84 cf 3b 73 b6 04 50 ff 23 0c dc b6 b1 b1 9b 15 09 ee b4 82 f6 96 c4 f1 c7 05 c0 0f 74 02 16 18 3a 12");
    let actual = yescrypt(b"p", b"s", 1, 16, 8, 1, 10, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("p", "s", 182, 16, 8, 1, 0, 0) = c8 c7 ff 11 22 b0 b2 91 c3 f2 60 89 48 78 2c d6 89 cc 45 57 90 17 aa a5 ff 8b aa 74 a6 32 ec 99 c3 d6 69 30 fb 20 23 bb
#[test]
fn kat21() {
    const EXPECTED: [u8; 40] = hex!("c8 c7 ff 11 22 b0 b2 91 c3 f2 60 89 48 78 2c d6 89 cc 45 57 90 17 aa a5 ff 8b aa 74 a6 32 ec 99 c3 d6 69 30 fb 20 23 bb");
    let actual = yescrypt(b"p", b"s", 182, 16, 8, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("p", "s", 1, 16, 8, 1, 0, 0) = 9d d6 36 c2 d0 bb 92 34 52 86 ef da f8 a6 8c fc 1b 4f fd c4 b1 ad ac cc 7d 86 4b 9a 67 87 b8 5d 6a e0 f5 28 0d a8 88 9f
#[test]
fn kat22() {
    const EXPECTED: [u8; 40] = hex!("9d d6 36 c2 d0 bb 92 34 52 86 ef da f8 a6 8c fc 1b 4f fd c4 b1 ad ac cc 7d 86 4b 9a 67 87 b8 5d 6a e0 f5 28 0d a8 88 9f");
    let actual = yescrypt(b"p", b"s", 1, 16, 8, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("p", "s", 182, 16, 8, 1, 0, 0) = c8 c7 ff 11 22 b0 b2 91 c3 f2 60 89 48 78 2c d6 89 cc 45 57 90 17 aa a5 ff 8b aa 74 a6 32 ec 99
#[test]
fn kat23() {
    const EXPECTED: [u8; 32] = hex!("c8 c7 ff 11 22 b0 b2 91 c3 f2 60 89 48 78 2c d6 89 cc 45 57 90 17 aa a5 ff 8b aa 74 a6 32 ec 99");
    let actual = yescrypt(b"p", b"s", 182, 16, 8, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

// yescrypt("p", "s", 182, 16, 8, 1, 0, 0) = c8 c7 ff 11 22 b0 b2 91
#[test]
fn kat24() {
    const EXPECTED: [u8; 8] = hex!("c8 c7 ff 11 22 b0 b2 91");
    let actual = yescrypt(b"p", b"s", 182, 16, 8, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}
