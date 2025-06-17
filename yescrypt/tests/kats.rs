//! Adapted from the reference implementation's `TESTS-OK`.
//! <https://github.com/openwall/yescrypt/blob/e5873f8/TESTS-OK>

use hex_literal::hex;
use yescrypt::yescrypt_kdf;

#[test]
fn kat0() {
    const EXPECTED: [u8; 64] = hex!(
        "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
        "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
    );
    let actual = yescrypt_kdf(b"", b"", 0, 16, 1, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat1() {
    const EXPECTED: [u8; 8] = hex!("77d6576238657b20");
    let actual = yescrypt_kdf(b"", b"", 0, 16, 1, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat2() {
    const EXPECTED: [u8; 64] = hex!(
        "efad0c23314cb572bc3cfb1543da42f8a8b073004c866b64ab5055a4f09fa5f5"
        "71142ebfe7e05a3b92c432f31dea95ad5f9c854b6456462f4bd0f732b7cdc549"
    );
    let actual = yescrypt_kdf(b"", b"", 0, 4, 1, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat3() {
    const EXPECTED: [u8; 64] = hex!(
        "85dda48c9ec9de2f7f1ae8b4dfeda51f8b6d56f3081be1a7c0833ba2719a36ab"
        "02885dae36557d342686b17ba75f2c217792de0970ab1d07a9c750936d31426f"
    );
    let actual = yescrypt_kdf(b"", b"", 1, 4, 1, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat4() {
    const EXPECTED: [u8; 8] = hex!("85dda48c9ec9de2f");
    let actual = yescrypt_kdf(b"", b"", 1, 4, 1, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat5() {
    const EXPECTED: [u8; 64] = hex!(
        "4baa8cd8608ba91f3e3439d9ec4fae8f9fc092d9ca22b7377e31ae5b9ad7877c"
        "1168691162dd0e5ef049e570650cbed4384ad60534fb0cbed19ff3f033c94b0c"
    );
    let actual = yescrypt_kdf(b"", b"", 1, 4, 1, 1, 1, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat6() {
    const EXPECTED: [u8; 64] = hex!(
        "e6e8bba09b6412ffb0b3cc35e37d0b782a47fbaadc57a076d7c6cc2e70919a1b"
        "8d4738c4f83355690742d9bed71c3b8fb0d7eb086ab134c5e55707c2c13c75ef"
    );
    let actual = yescrypt_kdf(b"", b"", 1, 4, 1, 1, 2, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat7() {
    const EXPECTED: [u8; 64] = hex!(
        "acd9a4201cf4a476ecf7baa6113d86fb65cd07102b4004e4f9d99cd34255a108"
        "997d70ae0a64bf0a4d96c173abf88279c1a94ad9bdf168edfbbd90f66ed5c80d"
    );
    let actual = yescrypt_kdf(b"", b"", 1, 4, 1, 1, 3, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat8() {
    const EXPECTED: [u8; 33] =
        hex!("acd9a4201cf4a476ecf7baa6113d86fb65cd07102b4004e4f9d99cd34255a10899");
    let actual = yescrypt_kdf(b"", b"", 1, 4, 1, 1, 3, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat9() {
    const EXPECTED: [u8; 32] =
        hex!("acd9a4201cf4a476ecf7baa6113d86fb65cd07102b4004e4f9d99cd34255a108");
    let actual = yescrypt_kdf(b"", b"", 1, 4, 1, 1, 3, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat10() {
    const EXPECTED: [u8; 31] =
        hex!("acd9a4201cf4a476ecf7baa6113d86fb65cd07102b4004e4f9d99cd34255a1");
    let actual = yescrypt_kdf(b"", b"", 1, 4, 1, 1, 3, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat11() {
    const EXPECTED: [u8; 1] = hex!("ac");
    let actual = yescrypt_kdf(b"", b"", 1, 4, 1, 1, 3, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat12() {
    const EXPECTED: [u8; 64] = hex!(
        "0cd5af76eb241df8119a9a122ae36920bcc7f414b9c0d58f45008060dade46b0"
        "c80922bdcc16a3ab5d201d4c6140c671be1f75272ca904739d5ad1ff672b0c21"
    );
    let actual = yescrypt_kdf(b"", b"", 182, 4, 1, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat13() {
    const EXPECTED: [u8; 4] = hex!("0cd5af76");
    let actual = yescrypt_kdf(b"", b"", 182, 4, 1, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat14() {
    const EXPECTED: [u8; 64] = hex!(
        "23b6adf0b60c9a997f58583d80cda48c638cdc2f289edf93a70807725a0d35c4"
        "68ca362c5557cc04b6811e2e730841f526d8f4f7acfbfa9e06fe1f383a71155e"
    );
    let actual = yescrypt_kdf(b"", b"", 182, 4, 1, 1, 1, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat15() {
    const EXPECTED: [u8; 33] =
        hex!("23b6adf0b60c9a997f58583d80cda48c638cdc2f289edf93a70807725a0d35c468");
    let actual = yescrypt_kdf(b"", b"", 182, 4, 1, 1, 1, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat16() {
    const EXPECTED: [u8; 32] =
        hex!("23b6adf0b60c9a997f58583d80cda48c638cdc2f289edf93a70807725a0d35c4");
    let actual = yescrypt_kdf(b"", b"", 182, 4, 1, 1, 1, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat17() {
    const EXPECTED: [u8; 31] =
        hex!("23b6adf0b60c9a997f58583d80cda48c638cdc2f289edf93a70807725a0d35");
    let actual = yescrypt_kdf(b"", b"", 182, 4, 1, 1, 1, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat18() {
    const EXPECTED: [u8; 1] = hex!("23");
    let actual = yescrypt_kdf(b"", b"", 182, 4, 1, 1, 1, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat19() {
    const EXPECTED: [u8; 40] =
        hex!("e1f981733a94052fcd7acb1405df0bbde8e499b6a1331b775909b48c2f516c40dcc8301635b7237b");
    let actual = yescrypt_kdf(b"p", b"s", 182, 16, 8, 1, 10, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat20() {
    const EXPECTED: [u8; 40] =
        hex!("9e7a4097644284cf3b73b60450ff230cdcb6b1b19b1509eeb482f696c4f1c705c00f740216183a12");
    let actual = yescrypt_kdf(b"p", b"s", 1, 16, 8, 1, 10, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat21() {
    const EXPECTED: [u8; 40] =
        hex!("c8c7ff1122b0b291c3f2608948782cd689cc45579017aaa5ff8baa74a632ec99c3d66930fb2023bb");
    let actual = yescrypt_kdf(b"p", b"s", 182, 16, 8, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat22() {
    const EXPECTED: [u8; 40] =
        hex!("9dd636c2d0bb92345286efdaf8a68cfc1b4ffdc4b1adaccc7d864b9a6787b85d6ae0f5280da8889f");
    let actual = yescrypt_kdf(b"p", b"s", 1, 16, 8, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat23() {
    const EXPECTED: [u8; 32] =
        hex!("c8c7ff1122b0b291c3f2608948782cd689cc45579017aaa5ff8baa74a632ec99");
    let actual = yescrypt_kdf(b"p", b"s", 182, 16, 8, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}

#[test]
fn kat24() {
    const EXPECTED: [u8; 8] = hex!("c8c7ff1122b0b291");
    let actual = yescrypt_kdf(b"p", b"s", 182, 16, 8, 1, 0, 0, EXPECTED.len());
    assert_eq!(EXPECTED.as_slice(), actual.as_slice());
}
