use balloon_hash::{Algorithm, Balloon, Params};
use digest::array::Array;
use hex_literal::hex;

struct TestVector {
    password: &'static [u8],
    salt: &'static [u8],
    s_cost: u32,
    t_cost: u32,
    output: [u8; 32],
}

/// Tested with the following implementations:
/// - <https://github.com/nachonavarro/balloon-hashing>
/// - <https://github.com/nogoegst/balloon>
const TEST_VECTORS: &[TestVector] = &[
    TestVector {
        password: b"hunter42",
        salt: b"examplesalt",
        s_cost: 1024,
        t_cost: 3,
        output: hex!("716043dff777b44aa7b88dcbab12c078abecfac9d289c5b5195967aa63440dfb"),
    },
    TestVector {
        password: b"",
        salt: b"salt",
        s_cost: 3,
        t_cost: 3,
        output: hex!("5f02f8206f9cd212485c6bdf85527b698956701ad0852106f94b94ee94577378"),
    },
    TestVector {
        password: b"password",
        salt: b"",
        s_cost: 3,
        t_cost: 3,
        output: hex!("20aa99d7fe3f4df4bd98c655c5480ec98b143107a331fd491deda885c4d6a6cc"),
    },
    TestVector {
        password: b"\0",
        salt: b"\0",
        s_cost: 3,
        t_cost: 3,
        output: hex!("4fc7e302ffa29ae0eac31166cee7a552d1d71135f4e0da66486fb68a749b73a4"),
    },
    TestVector {
        password: b"password",
        salt: b"salt",
        s_cost: 1,
        t_cost: 1,
        output: hex!("eefda4a8a75b461fa389c1dcfaf3e9dfacbc26f81f22e6f280d15cc18c417545"),
    },
];

#[test]
fn test_vectors() {
    for test_vector in TEST_VECTORS {
        let balloon = Balloon::<sha2::Sha256>::new(
            Algorithm::Balloon,
            Params::new(test_vector.s_cost, test_vector.t_cost, 1).unwrap(),
            None,
        );

        let mut memory = vec![Array::default(); balloon.params.s_cost.get() as usize];

        assert_eq!(
            balloon
                .hash_with_memory(test_vector.password, test_vector.salt, &mut memory)
                .unwrap()
                .as_slice(),
            test_vector.output,
        );
    }
}

#[cfg(all(feature = "password-hash", feature = "alloc"))]
#[test]
fn hash_simple_retains_configured_params() {
    use balloon_hash::{PasswordHasher, Salt};
    use sha2::Sha256;

    /// Example password only: don't use this as a real password!!!
    const EXAMPLE_PASSWORD: &[u8] = b"hunter42";

    /// Example salt value. Don't use a static salt value!!!
    const EXAMPLE_SALT: &str = "examplesaltvalue";

    // Non-default but valid parameters
    let t_cost = 4;
    let s_cost = 2048;
    let p_cost = 2;

    let params = Params::new(s_cost, t_cost, p_cost).unwrap();
    let hasher = Balloon::<Sha256>::new(Algorithm::default(), params, None);
    let salt = Salt::from_b64(EXAMPLE_SALT).unwrap();
    let hash = hasher.hash_password(EXAMPLE_PASSWORD, salt).unwrap();

    assert_eq!(hash.version.unwrap(), 1);

    for &(param, value) in &[("t", t_cost), ("s", s_cost), ("p", p_cost)] {
        assert_eq!(
            hash.params
                .get(param)
                .and_then(|p| p.decimal().ok())
                .unwrap(),
            value
        );
    }
}
