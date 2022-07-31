use sha_crypt::{sha512_crypt_b64, Sha512Params, ROUNDS_MAX, ROUNDS_MIN};

#[cfg(feature = "simple")]
use sha_crypt::{sha512_check, sha512_simple};

struct TestVector {
    input: &'static str,
    salt: &'static str,
    result: &'static str,
    rounds: usize,
}

const TEST_VECTORS: &[TestVector] = &[
    TestVector {
        input: "Hello world!",
        salt: "saltstring",
        result:
            "svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
        rounds: 5_000,
    },
    TestVector {
        input: "Hello world!",
        salt: "saltstringsaltstring",
        result:
            "OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.",
        rounds: 10_000,
    },
    TestVector {
        input: "This is just a test",
        salt: "toolongsaltstring",
        result:
            "lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0",
        rounds: 5_000,
    },
    // 63 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        salt: "kf8.jB3ZLrhG2/n1",
        result:
            "BZk4ni5Rx3KgyM7vd48EpPgr8AoICCq5HRQPu6vNf6t6xnJ3xNu7MMMBXh/3eUZ5ql.mBqjNhlYUWHBqjKRkU/",
        rounds: 5_000,
    },
    // 64 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 64 length
        salt: "JKb8lkbDWryxdaRL",
        result:
            "dLVyYl.G1KhMak97BNNO7vV2upvwcQ3hKrQjO8xn.V/ucmN4ogytaGbIEfBrNv4YLtbpjgV240ldDgkP9M9S7.",
        rounds: 5_000,
    },
    // 65 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 65 length
        salt: "JmlLQtPDXkxMbdFc",
        result:
            "lO/BGRK6dKXMaRafyLMZl9wkxvdCobed0ppRHYJtCfatf6yGLghCs.rq.ifz4YezxCHmQG7lpqm4W46xsNnBm0",
        rounds: 5_000,
    },
    // 127 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        salt: "/1VCrzVUrr9Nmmkl",
        result:
            "zp5KH/GGAMr3pQap8GbQ2Qgp3EjvI4o7kurGx9YNtwzN5eKvuWGuR/LNMa5qANyeHl2ROMMd0WkX24ttkiGIE1",
        rounds: 5_000,
    },
    // 128 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        salt: "mpyXfdM3cczHJWG6",
        result:
            "vvNL55Todp53rsMLKgBJHsCC2lKj4AwYWWF/ywz7UVqBxj7F00UUI2an7R5amwBTL4DibkvKMb3Oj5dk4I1Y4.",
        rounds: 5_000,
    },
    // 129 length password 
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        salt: "idU8Ptdv2tVGArtN",
        result:
            "uM8hU3Ot4nmDtcMvMyccUW2vT6uI2cM6MpWDslBlyO0jghVdKYB7RafnmQQPrA8QMauX8qrnX5Fs9ST5y/zUS1",
        rounds: 5_000,
    },
];

#[test]
fn test_sha512_crypt() {
    for t in TEST_VECTORS {
        let params = Sha512Params::new(t.rounds).expect("Rounds error");
        let result = sha512_crypt_b64(t.input.as_bytes(), t.salt.as_bytes(), &params).unwrap();
        assert!(result == t.result);
    }
}

#[test]
fn test_sha512_crypt_invalid_rounds() {
    let params = Sha512Params::new(ROUNDS_MAX + 1);
    assert!(params.is_err());

    let params = Sha512Params::new(ROUNDS_MIN - 1);
    assert!(params.is_err());
}

#[cfg(feature = "simple")]
#[test]
fn test_sha512_check() {
    let pw = "foobar";
    let s = "$6$bbe605c2cce4c642$BiBOywFAm9kdv6ZPpj2GaKVqeh/.c21pf1uFBaq.e59KEE2Ej74iJleXaLXURYV6uh5LF4K7dDc4vtRtPiiKB/";
    assert!(sha512_check(pw, s).is_ok());
}

#[cfg(feature = "simple")]
#[test]
fn test_sha512_check_with_rounds() {
    let pw = "foobar";
    let s = "$6$rounds=100000$exn6tVc2j/MZD8uG$BI1Xh8qQSK9J4m14uwy7abn.ctj/TIAzlaVCto0MQrOFIeTXsc1iwzH16XEWo/a7c7Y9eVJvufVzYAs4EsPOy0";
    assert!(sha512_check(pw, s).is_ok());
}

#[cfg(feature = "simple")]
#[test]
fn test_sha512_simple_check_roundtrip() {
    let pw = "this is my password";
    let params = Sha512Params::new(5_000).expect("Rounds error");

    let r = sha512_simple(&pw, &params);
    assert!(r.is_ok());
    let hash = r.unwrap();

    let c_r = sha512_check(&pw, &hash);
    assert!(c_r.is_ok());
}

#[cfg(feature = "simple")]
#[test]
fn test_sha512_unexpected_prefix() {
    let pw = "foobar";
    let s = "SHOULDNOTBEHERE$6$rounds=100000$exn6tVc2j/MZD8uG$BI1Xh8qQSK9J4m14uwy7abn.ctj/TIAzlaVCto0MQrOFIeTXsc1iwzH16XEWo/a7c7Y9eVJvufVzYAs4EsPOy0";
    assert!(!sha512_check(pw, s).is_ok());
}

#[cfg(feature = "simple")]
#[test]
fn test_sha512_wrong_id() {
    // wrong id '7'
    let pw = "foobar";
    let s = "$7$rounds=100000$exn6tVc2j/MZD8uG$BI1Xh8qQSK9J4m14uwy7abn.ctj/TIAzlaVCto0MQrOFIeTXsc1iwzH16XEWo/a7c7Y9eVJvufVzYAs4EsPOy0";
    assert!(!sha512_check(pw, s).is_ok());
}

#[cfg(feature = "simple")]
#[test]
fn test_sha512_missing_trailing_slash() {
    // Missing trailing slash
    let pw = "abc";
    let s = "$6$rounds=656000$Ykk6fjI2sU3/uprV$Z6yV/9Z741lfroSSzB9MwxSRnGeI9Z74hBkgNsHuojQJxZ9XjPkHg9jqqGLvWZ586wqnSSx5vrXZdhrMSZZE4";
    assert!(!sha512_check(pw, s).is_ok());
}
