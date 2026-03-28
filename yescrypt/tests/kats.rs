//! Adapted from the reference implementation's `TESTS-OK`.
//! <https://github.com/openwall/yescrypt/blob/e5873f8/TESTS-OK>

use yescrypt::{Mode, Params, yescrypt};

#[path = "../data/test_vectors.rs"]
mod test_vectors;
use test_vectors::TEST_VECTORS;

#[test]
fn kats() {
    for test_vector in TEST_VECTORS {
        let mut actual = vec![0u8; test_vector.output.len()];
        yescrypt(
            test_vector.password,
            test_vector.salt,
            &test_vector.params(),
            &mut actual,
        )
        .unwrap();
        assert_eq!(test_vector.output, actual.as_slice());
    }
}

/// Regression test for RustCrypto/password-hashes#680
#[test]
fn regression680() {
    let params = Params::new(Mode::default(), 4096, 32, 1).unwrap();
    let salt: &[u8] = &[
        198, 183, 30, 133, 125, 115, 128, 76, 161, 57, 49, 10, 94, 249, 166, 29,
    ];
    let mut output = [0u8; 32];
    yescrypt(b"password", salt, &params, &mut output).unwrap();
    assert_eq!(
        output,
        [
            197, 98, 241, 33, 68, 79, 182, 214, 153, 96, 65, 173, 79, 243, 43, 4, 53, 180, 211,
            128, 155, 167, 159, 129, 73, 143, 205, 236, 163, 185, 102, 186
        ]
    );
}
