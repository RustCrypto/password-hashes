use sha_crypt::{
    sha256_crypt_b64, sha512_crypt_b64, Sha256Params, Sha512Params, ROUNDS_MAX, ROUNDS_MIN,
};

#[cfg(feature = "simple")]
use sha_crypt::{sha256_check, sha256_simple, sha512_check, sha512_simple};

struct TestVector {
    input: &'static str,
    salt: &'static str,
    result_sha256: &'static str,
    result_sha512: &'static str,
    rounds: u32,
}

const TEST_VECTORS: &[TestVector] = &[
    TestVector {
        input: "Hello world!",
        salt: "saltstring",
        result_sha256:
            "5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
        result_sha512:
            "svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
        rounds: 5_000,
    },
    TestVector {
        input: "Hello world!",
        salt: "saltstringsaltstring",
        result_sha256: "3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA",
        result_sha512:
            "OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.",
        rounds: 10_000,
    },
    TestVector {
        input: "This is just a test",
        salt: "toolongsaltstring",
        result_sha256:
            "Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5",
        result_sha512:
            "lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0",
        rounds: 5_000,
    },
    // 63 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        salt: "kf8.jB3ZLrhG2/n1",
        result_sha256: "DjWX2SQlslxT/jON7Gof6T4UodbHrqW0Lwl7xLT2gu8",
        result_sha512:
            "BZk4ni5Rx3KgyM7vd48EpPgr8AoICCq5HRQPu6vNf6t6xnJ3xNu7MMMBXh/3eUZ5ql.mBqjNhlYUWHBqjKRkU/",
        rounds: 5_000,
    },
    // 64 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 64 length
        salt: "JKb8lkbDWryxdaRL",
        result_sha256: "X2024tVMdQy9vnRU/dnWB0eL4dpfJvgD3g9o0eE95d7",
        result_sha512:
            "dLVyYl.G1KhMak97BNNO7vV2upvwcQ3hKrQjO8xn.V/ucmN4ogytaGbIEfBrNv4YLtbpjgV240ldDgkP9M9S7.",
        rounds: 5_000,
    },
    // 65 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 65 length
        salt: "JmlLQtPDXkxMbdFc",
        result_sha256: "MVZTo9AdKikQwK5sBlSQ/X7mUH19GoFGrmRr0XxcUr6",
        result_sha512:
            "lO/BGRK6dKXMaRafyLMZl9wkxvdCobed0ppRHYJtCfatf6yGLghCs.rq.ifz4YezxCHmQG7lpqm4W46xsNnBm0",
        rounds: 5_000,
    },
    // 127 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        salt: "/1VCrzVUrr9Nmmkl",
        result_sha256: "SzBUUlAa0OOcJ4RkWAEcxPCu9KvgM3XV2Wt1Or7Qnm9",
        result_sha512:
            "zp5KH/GGAMr3pQap8GbQ2Qgp3EjvI4o7kurGx9YNtwzN5eKvuWGuR/LNMa5qANyeHl2ROMMd0WkX24ttkiGIE1",
        rounds: 5_000,
    },
    // 128 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        salt: "mpyXfdM3cczHJWG6",
        result_sha256: "mDy6Ir4NZkSLjfI1jo.P8FQDl5cf51ZpOYO9VAiYzK2",
        result_sha512:
            "vvNL55Todp53rsMLKgBJHsCC2lKj4AwYWWF/ywz7UVqBxj7F00UUI2an7R5amwBTL4DibkvKMb3Oj5dk4I1Y4.",
        rounds: 5_000,
    },
    // 129 length password 
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        salt: "idU8Ptdv2tVGArtN",
        result_sha256: "mijVpmWD4y0vuT.2Ux0XMwvpis59xfeu3Mhm1TIK7T9",
        result_sha512:
            "uM8hU3Ot4nmDtcMvMyccUW2vT6uI2cM6MpWDslBlyO0jghVdKYB7RafnmQQPrA8QMauX8qrnX5Fs9ST5y/zUS1",
        rounds: 5_000,
    },
];

#[test]
fn test_sha512_crypt() {
    for t in TEST_VECTORS {
        let params = Sha512Params::new(t.rounds).expect("Rounds error");
        let result = sha512_crypt_b64(t.input.as_bytes(), t.salt.as_bytes(), &params);
        assert!(result == t.result_sha512);
    }
}

#[test]
fn test_sha256_crypt() {
    for t in TEST_VECTORS {
        let params = Sha256Params::new(t.rounds).expect("Rounds error");
        let result = sha256_crypt_b64(t.input.as_bytes(), t.salt.as_bytes(), &params);
        println!("result  {:?}", result);
        println!("correct {:?}", t.result_sha256);
        assert!(result == t.result_sha256);
    }
}

#[test]
fn test_sha512_crypt_invalid_rounds() {
    let params = Sha512Params::new(ROUNDS_MAX + 1);
    assert!(params.is_err());

    let params = Sha512Params::new(ROUNDS_MIN - 1);
    assert!(params.is_err());
}

#[test]
fn test_sha256_crypt_invalid_rounds() {
    let params = Sha256Params::new(ROUNDS_MAX + 1);
    assert!(params.is_err());

    let params = Sha256Params::new(ROUNDS_MIN - 1);
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
fn test_sha256_check() {
    let pw = "foobar";
    let s = "$5$9aEeVXnCiCNHUjO/$FrVBcjyJukRaE6inMYazyQv1DBnwaKfom.71ebgQR/0";
    assert!(sha256_check(pw, s).is_ok());
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
fn test_sha256_check_with_rounds() {
    let pw = "foobar";
    let s = "$5$rounds=100000$PhW/wpSsmgIMKsTW$d9kDD8dQNu3r0Ky.xcOEhdin6EQRebrHfNKDRwWP/pB";
    assert!(sha256_check(pw, s).is_ok());
}

#[cfg(feature = "simple")]
#[test]
fn test_sha512_simple_check_roundtrip() {
    let pw = "this is my password";
    let params = Sha512Params::new(5_000).expect("Rounds error");

    let hash = sha512_simple(pw, &params);

    let c_r = sha512_check(pw, &hash);
    assert!(c_r.is_ok());
}

#[cfg(feature = "simple")]
#[test]
fn test_sha256_simple_check_roundtrip() {
    let pw = "this is my password";
    let params = Sha256Params::new(5_000).expect("Rounds error");

    let hash = sha256_simple(pw, &params);

    let c_r = sha256_check(pw, &hash);
    assert!(c_r.is_ok());
}

#[cfg(feature = "simple")]
#[test]
fn test_sha512_unexpected_prefix() {
    let pw = "foobar";
    let s = "SHOULDNOTBEHERE$6$rounds=100000$exn6tVc2j/MZD8uG$BI1Xh8qQSK9J4m14uwy7abn.ctj/TIAzlaVCto0MQrOFIeTXsc1iwzH16XEWo/a7c7Y9eVJvufVzYAs4EsPOy0";
    assert!(sha512_check(pw, s).is_err());
}

#[cfg(feature = "simple")]
#[test]
fn test_sha256_unexpected_prefix() {
    let pw = "foobar";
    let s = "SHOULDNOTBEHERE$6$rounds=100000$exn6tVc2j/MZD8uG$BI1Xh8qQSK9J4m14uwy7abn.ctj/TIAzlaVCto0MQrOFIeTXsc1iwzH16XEWo/a7c7Y9eVJvufVzYAs4EsPOy0";
    assert!(sha256_check(pw, s).is_err());
}

#[cfg(feature = "simple")]
#[test]
fn test_sha512_wrong_id() {
    // wrong id '7'
    let pw = "foobar";
    let s = "$7$rounds=100000$exn6tVc2j/MZD8uG$BI1Xh8qQSK9J4m14uwy7abn.ctj/TIAzlaVCto0MQrOFIeTXsc1iwzH16XEWo/a7c7Y9eVJvufVzYAs4EsPOy0";
    assert!(sha512_check(pw, s).is_err());
}

#[cfg(feature = "simple")]
#[test]
fn test_sha256_wrong_id() {
    // wrong id '7'
    let pw = "foobar";
    let s = "$7$rounds=100000$exn6tVc2j/MZD8uG$BI1Xh8qQSK9J4m14uwy7abn.ctj/TIAzlaVCto0MQrOFIeTXsc1iwzH16XEWo/a7c7Y9eVJvufVzYAs4EsPOy0";
    assert!(sha256_check(pw, s).is_err());
}

#[cfg(feature = "simple")]
#[test]
fn test_sha512_missing_trailing_slash() {
    // Missing trailing slash
    let pw = "abc";
    let s = "$6$rounds=656000$Ykk6fjI2sU3/uprV$Z6yV/9Z741lfroSSzB9MwxSRnGeI9Z74hBkgNsHuojQJxZ9XjPkHg9jqqGLvWZ586wqnSSx5vrXZdhrMSZZE4";
    assert!(sha512_check(pw, s).is_err());
}

#[cfg(feature = "simple")]
#[test]
fn test_sha256_missing_trailing_slash() {
    // Missing trailing slash
    let pw = "abc";
    let s = "$6$rounds=656000$Ykk6fjI2sU3/uprV$Z6yV/9Z741lfroSSzB9MwxSRnGeI9Z74hBkgNsHuojQJxZ9XjPkHg9jqqGLvWZ586wqnSSx5vrXZdhrMSZZE4";
    assert!(sha256_check(pw, s).is_err());
}
