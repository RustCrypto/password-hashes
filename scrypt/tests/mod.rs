#[cfg(feature = "simple")]
use scrypt::errors::CheckError;
use scrypt::{scrypt, ScryptParams};
#[cfg(feature = "simple")]
use scrypt::{scrypt_check, scrypt_simple};

struct Test {
    password: &'static str,
    salt: &'static str,
    log_n: u8,
    r: u32,
    p: u32,
    expected: Vec<u8>,
}

// Test vectors from [1]. The last test vector is omitted because it takes
// too long to run.
fn tests() -> Vec<Test> {
    vec![
        Test {
            password: "",
            salt: "",
            log_n: 4,
            r: 1,
            p: 1,
            expected: vec![
                0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20, 0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a,
                0x04, 0x97, 0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8, 0xdf, 0xdf, 0xfa, 0x3f,
                0xed, 0xe2, 0x14, 0x42, 0xfc, 0xd0, 0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8, 0x32, 0x6a,
                0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17, 0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28,
                0xcf, 0x35, 0xe2, 0x0c, 0x38, 0xd1, 0x89, 0x06,
            ],
        },
        Test {
            password: "password",
            salt: "NaCl",
            log_n: 10,
            r: 8,
            p: 16,
            expected: vec![
                0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00, 0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01,
                0xe9, 0xfe, 0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30, 0xe7, 0x73, 0x76, 0x63,
                0x4b, 0x37, 0x31, 0x62, 0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88, 0x6f, 0xf1,
                0x09, 0x27, 0x9d, 0x98, 0x30, 0xda, 0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d,
                0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40,
            ],
        },
        Test {
            password: "pleaseletmein",
            salt: "SodiumChloride",
            log_n: 14,
            r: 8,
            p: 1,
            expected: vec![
                0x70, 0x23, 0xbd, 0xcb, 0x3a, 0xfd, 0x73, 0x48, 0x46, 0x1c, 0x06, 0xcd, 0x81, 0xfd,
                0x38, 0xeb, 0xfd, 0xa8, 0xfb, 0xba, 0x90, 0x4f, 0x8e, 0x3e, 0xa9, 0xb5, 0x43, 0xf6,
                0x54, 0x5d, 0xa1, 0xf2, 0xd5, 0x43, 0x29, 0x55, 0x61, 0x3f, 0x0f, 0xcf, 0x62, 0xd4,
                0x97, 0x05, 0x24, 0x2a, 0x9a, 0xf9, 0xe6, 0x1e, 0x85, 0xdc, 0x0d, 0x65, 0x1e, 0x40,
                0xdf, 0xcf, 0x01, 0x7b, 0x45, 0x57, 0x58, 0x87,
            ],
        },
    ]
}

#[test]
fn test_scrypt() {
    let tests = tests();
    for t in tests.iter() {
        let mut result = vec![0u8; t.expected.len()];
        let params = ScryptParams::new(t.log_n, t.r, t.p).unwrap();
        scrypt(
            t.password.as_bytes(),
            t.salt.as_bytes(),
            &params,
            &mut result,
        )
        .unwrap();
        assert!(result == t.expected);
    }
}

#[cfg(feature = "simple")]
fn test_scrypt_simple(log_n: u8, r: u32, p: u32) {
    let password = "password";

    let params = ScryptParams::new(log_n, r, p).unwrap();
    let out1 = scrypt_simple(password, &params).unwrap();
    let out2 = scrypt_simple(password, &params).unwrap();

    // This just makes sure that a salt is being applied. It doesn't verify that
    // that salt is cryptographically strong, however.
    assert!(out1 != out2);

    assert_eq!(scrypt_check(password, &out1[..]), Ok(()));
    assert_eq!(scrypt_check(password, &out2[..]), Ok(()));

    assert_eq!(
        scrypt_check("wrong", &out1[..]),
        Err(CheckError::HashMismatch)
    );
    assert_eq!(
        scrypt_check("wrong", &out2[..]),
        Err(CheckError::HashMismatch)
    );
}

#[cfg(feature = "simple")]
#[test]
fn test_scrypt_simple_compact() {
    // These parameters are intentionally very weak - the goal is to make
    // the test run quickly!
    test_scrypt_simple(7, 8, 1);
}

#[cfg(feature = "simple")]
#[test]
fn test_scrypt_simple_expanded() {
    // These parameters are intentionally very weak - the goal is to make
    // the test run quickly!
    test_scrypt_simple(3, 1, 256);
}
