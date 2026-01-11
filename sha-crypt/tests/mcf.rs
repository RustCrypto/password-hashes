#![cfg(feature = "password-hash")]

use base64ct::{Base64ShaCrypt, Encoding};
use mcf::PasswordHash;
use sha_crypt::{
    Algorithm, Params, ShaCrypt,
    password_hash::{CustomizedPasswordHasher, Error, PasswordVerifier},
};

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
        result_sha256: "5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
        result_sha512: "svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
        rounds: 5_000,
    },
    TestVector {
        input: "Hello world!",
        salt: "saltstringsaltstring",
        result_sha256: "3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA",
        result_sha512: "OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.",
        rounds: 10_000,
    },
    TestVector {
        input: "This is just a test",
        salt: "toolongsaltstring",
        result_sha256: "Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5",
        result_sha512: "lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0",
        rounds: 5_000,
    },
    // 63 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        salt: "kf8.jB3ZLrhG2/n1",
        result_sha256: "DjWX2SQlslxT/jON7Gof6T4UodbHrqW0Lwl7xLT2gu8",
        result_sha512: "BZk4ni5Rx3KgyM7vd48EpPgr8AoICCq5HRQPu6vNf6t6xnJ3xNu7MMMBXh/3eUZ5ql.mBqjNhlYUWHBqjKRkU/",
        rounds: 5_000,
    },
    // 64 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 64 length
        salt: "JKb8lkbDWryxdaRL",
        result_sha256: "X2024tVMdQy9vnRU/dnWB0eL4dpfJvgD3g9o0eE95d7",
        result_sha512: "dLVyYl.G1KhMak97BNNO7vV2upvwcQ3hKrQjO8xn.V/ucmN4ogytaGbIEfBrNv4YLtbpjgV240ldDgkP9M9S7.",
        rounds: 5_000,
    },
    // 65 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 65 length
        salt: "JmlLQtPDXkxMbdFc",
        result_sha256: "MVZTo9AdKikQwK5sBlSQ/X7mUH19GoFGrmRr0XxcUr6",
        result_sha512: "lO/BGRK6dKXMaRafyLMZl9wkxvdCobed0ppRHYJtCfatf6yGLghCs.rq.ifz4YezxCHmQG7lpqm4W46xsNnBm0",
        rounds: 5_000,
    },
    // 127 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        salt: "/1VCrzVUrr9Nmmkl",
        result_sha256: "SzBUUlAa0OOcJ4RkWAEcxPCu9KvgM3XV2Wt1Or7Qnm9",
        result_sha512: "zp5KH/GGAMr3pQap8GbQ2Qgp3EjvI4o7kurGx9YNtwzN5eKvuWGuR/LNMa5qANyeHl2ROMMd0WkX24ttkiGIE1",
        rounds: 5_000,
    },
    // 128 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        salt: "mpyXfdM3cczHJWG6",
        result_sha256: "mDy6Ir4NZkSLjfI1jo.P8FQDl5cf51ZpOYO9VAiYzK2",
        result_sha512: "vvNL55Todp53rsMLKgBJHsCC2lKj4AwYWWF/ywz7UVqBxj7F00UUI2an7R5amwBTL4DibkvKMb3Oj5dk4I1Y4.",
        rounds: 5_000,
    },
    // 129 length password
    TestVector {
        input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        salt: "idU8Ptdv2tVGArtN",
        result_sha256: "mijVpmWD4y0vuT.2Ux0XMwvpis59xfeu3Mhm1TIK7T9",
        result_sha512: "uM8hU3Ot4nmDtcMvMyccUW2vT6uI2cM6MpWDslBlyO0jghVdKYB7RafnmQQPrA8QMauX8qrnX5Fs9ST5y/zUS1",
        rounds: 5_000,
    },
];

#[test]
fn hash_sha256_crypt() {
    let sha_crypt = ShaCrypt::from(Algorithm::Sha256Crypt);
    let mut any = false;

    for t in TEST_VECTORS {
        if let Ok(salt) = Base64ShaCrypt::decode_vec(&t.salt) {
            let params = Params::new(t.rounds).unwrap();
            let result = sha_crypt
                .hash_password_with_params(t.input.as_bytes(), &salt, params)
                .unwrap();

            assert_eq!(result.fields().last().unwrap().as_str(), t.result_sha256);
            any = true;
        }
    }

    assert!(any)
}

#[test]
fn hash_sha512_crypt() {
    let sha_crypt = ShaCrypt::default(); // default should be SHA-512
    let mut any = false;

    for t in TEST_VECTORS {
        if let Ok(salt) = Base64ShaCrypt::decode_vec(&t.salt) {
            let params = Params::new(t.rounds).unwrap();
            let result = sha_crypt
                .hash_password_with_params(t.input.as_bytes(), &salt, params)
                .unwrap();

            assert_eq!(result.fields().last().unwrap().as_str(), t.result_sha512);
            any = true;
        }
    }

    assert!(any)
}

#[test]
fn verify_sha256_crypt() {
    let sha_crypt = ShaCrypt::from(Algorithm::Sha256Crypt);

    for t in TEST_VECTORS {
        let mut hash = PasswordHash::from_id("6").unwrap();
        hash.push_str(&format!("rounds={}", t.rounds)).unwrap();
        hash.push_str(t.salt).unwrap();
        hash.push_str(t.result_sha512).unwrap();

        assert_eq!(sha_crypt.verify_password(t.input.as_bytes(), &hash), Ok(()));
    }

    assert_eq!(
        sha_crypt.verify_password(
            b"foobar",
            &PasswordHash::new("$5$9aEeVXnCiCNHUjO/$FrVBcjyJukRaE6inMYazyQv1DBnwaKfom.71ebgQR/0")
                .unwrap()
        ),
        Ok(())
    );

    assert_eq!(
        sha_crypt.verify_password(
            b"foobar",
            &PasswordHash::new(
                "$5$rounds=100000$PhW/wpSsmgIMKsTW$d9kDD8dQNu3r0Ky.xcOEhdin6EQRebrHfNKDRwWP/pB"
            )
            .unwrap()
        ),
        Ok(())
    );
}

#[test]
fn verify_sha512_crypt() {
    let sha_crypt = ShaCrypt::default(); // default should be SHA-512

    for t in TEST_VECTORS {
        let mut hash = PasswordHash::from_id("6").unwrap();
        hash.push_str(&format!("rounds={}", t.rounds)).unwrap();
        hash.push_str(t.salt).unwrap();
        hash.push_str(t.result_sha512).unwrap();

        assert_eq!(sha_crypt.verify_password(t.input.as_bytes(), &hash), Ok(()));
    }

    assert_eq!(
        sha_crypt.verify_password(
            b"foobar",
            &PasswordHash::new(
                "$6$bbe605c2cce4c642$BiBOywFAm9kdv6ZPpj2GaKVqeh/.c21pf1uFBaq.e59KEE2Ej74iJleXaLXURYV6uh5LF4K7dDc4vtRtPiiKB/"
            ).unwrap()
        ),
        Ok(())
    );

    assert_eq!(
        sha_crypt.verify_password(
            b"foobar",
            &PasswordHash::new(
                "$6$rounds=100000$exn6tVc2j/MZD8uG$BI1Xh8qQSK9J4m14uwy7abn.ctj/TIAzlaVCto0MQrOFIeTXsc1iwzH16XEWo/a7c7Y9eVJvufVzYAs4EsPOy0"
            ).unwrap()
        ),
        Ok(())
    );
}

#[cfg(feature = "password-hash")]
#[test]
fn test_wrong_id() {
    let sha_crypt = ShaCrypt::default();
    let passwd = b"foobar";

    // wrong id '7'
    let hash = PasswordHash::new("$7$rounds=100000$exn6tVc2j/MZD8uG$BI1Xh8qQSK9J4m14uwy7abn.ctj/TIAzlaVCto0MQrOFIeTXsc1iwzH16XEWo/a7c7Y9eVJvufVzYAs4EsPOy0").unwrap();
    let res = sha_crypt.verify_password(passwd, &hash);
    assert_eq!(res, Err(Error::Algorithm));
}
