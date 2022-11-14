use md5_crypt::md5_crypt_b64;

#[cfg(feature = "simple")]
use md5_crypt::{md5_check, md5_simple};

use std::str;

struct TestVector {
    input: &'static str,
    salt: &'static str,
    result: &'static str,
}

const TEST_VECTORS: &[TestVector] = &[
    TestVector {
        input: "",
        salt: "salt",
        result: "UsdFqFVB.FsuinRDK5eE..",
    },
    TestVector {
        input: "abc",
        salt: "salt",
        result: "Ix0K7gMcCieLMZGthf6yT1",
    },
    TestVector {
        input: "Hello world!",
        salt: "salt",
        result: "wa8aFuC3rkp5bjoBIGTc41",
    },
    TestVector {
        input: "Hello world!",
        salt: "saltsalt",
        result: "le8lFSqqnPaRFOlmAZpvH1",
    },
    TestVector {
        input: "This is just a test",
        salt: "saltsalt",
        result: "GG3.Tf92SRQMW0mClBXo..",
    },
    // 63 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        salt: "kf8.jB3Z",
        result: "UZFByQYndkZGAc9kqF4A21",
    },
    // 64 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 64 length
        salt: "kf8.jB3Z",
        result: ".XRGr/PlZPFr11frOZsYQ0",
    },
    // 65 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 65 length
        salt: "kf8.jB3Z",
        result: "xErCjUcXBWx7JNSY/bdJM1",
    },
    // 127 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        salt: "kf8.jB3Z",
        result: "ay9BDuVT.pV2B.EX6V4HC1",
    },
    // 128 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        salt: "kf8.jB3Z",
        result: "kZ6Ws32gDHOGf1DEqpBUq.",
    },
    // 129 length password 
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        salt: "kf8.jB3Z",
        result: "5hc1Ea4UM8OzOhdb2/WvW0",
    },
];

#[test]
fn test_md5_crypt() {
    for t in TEST_VECTORS {
        let result_array = md5_crypt_b64(t.input.as_bytes(), t.salt.as_bytes()).unwrap();
        let result = str::from_utf8(&result_array).unwrap();
        assert!(result == t.result);
    }
}

#[cfg(feature = "simple")]
#[test]
fn test_md5_check() {
    let pw = "foobar";
    let s = "$1$NoaSCTUg$j91ZS4vEeaHDdpecPbzkY0";
    assert!(md5_check(pw, s).is_ok());
}

#[cfg(feature = "simple")]
#[test]
fn test_md5_simple_check_roundtrip() {
    let pw = "this is my password";

    let r = md5_simple(&pw);
    assert!(r.is_ok());
    let hash = r.unwrap();

    let c_r = md5_check(&pw, &hash);
    assert!(c_r.is_ok());
}

#[cfg(feature = "simple")]
#[test]
fn test_md5_unexpected_prefix() {
    let pw = "foobar";
    let s = "SHOULDNOTBEHERE$1$WtWGiGnH$Ryci5v8qFuzlfj25Yye97";
    assert!(!md5_check(pw, s).is_ok());
}

#[cfg(feature = "simple")]
#[test]
fn test_md5_wrong_id() {
    // wrong id '2'
    let pw = "foobar";
    let s = "$2$WtWGiGnH$Ryci5v8qFuzlfj25Yye97";
    assert!(!md5_check(pw, s).is_ok());
}

#[cfg(feature = "simple")]
#[test]
fn test_md5_missing_trailing_slash() {
    // Missing trailing slash
    let pw = "abc";
    let s = "$1$/dUAwECj$E7lsyZl3NQqTePIPi4/42";
    assert!(!md5_check(pw, s).is_ok());
}
