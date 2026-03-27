use balloon_hash::{Algorithm, Balloon, Params};
use digest::array::Array;


#[path = "../data/mod.rs"]
mod data;
use data::TEST_VECTORS;

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
                .hash_password_with_memory(test_vector.password, test_vector.salt, &mut memory)
                .unwrap()
                .as_slice(),
            test_vector.output,
        );
    }
}

#[cfg(all(feature = "password-hash", feature = "alloc"))]
#[test]
fn password_hash_retains_configured_params() {
    use balloon_hash::PasswordHasher;
    use sha2::Sha256;

    /// Example password only: don't use this as a real password!!!
    const EXAMPLE_PASSWORD: &[u8] = b"hunter42";

    /// Example salt value. Don't use a static salt value!!!
    const EXAMPLE_SALT: &[u8] = b"example-salt";

    // Non-default but valid parameters
    let t_cost = 4;
    let s_cost = 2048;
    let p_cost = 2;

    let params = Params::new(s_cost, t_cost, p_cost).unwrap();
    let hasher = Balloon::<Sha256>::new(Algorithm::default(), params, None);
    let hash = hasher
        .hash_password_with_salt(EXAMPLE_PASSWORD, EXAMPLE_SALT)
        .unwrap();

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
