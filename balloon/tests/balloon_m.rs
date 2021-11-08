#![cfg(feature = "alloc")]

use balloon_hash::{Algorithm, Balloon, Params};
use hex_literal::hex;

struct TestVector {
    password: &'static [u8],
    salt: &'static [u8],
    s_cost: u32,
    t_cost: u32,
    p_cost: u32,
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
        p_cost: 4,
        output: hex!("1832bd8e5cbeba1cb174a13838095e7e66508e9bf04c40178990adbc8ba9eb6f"),
    },
    TestVector {
        password: b"",
        salt: b"salt",
        s_cost: 3,
        t_cost: 3,
        p_cost: 2,
        output: hex!("f8767fe04059cef67b4427cda99bf8bcdd983959dbd399a5e63ea04523716c23"),
    },
    TestVector {
        password: b"password",
        salt: b"",
        s_cost: 3,
        t_cost: 3,
        p_cost: 3,
        output: hex!("bcad257eff3d1090b50276514857e60db5d0ec484129013ef3c88f7d36e438d6"),
    },
    TestVector {
        password: b"password",
        salt: b"",
        s_cost: 3,
        t_cost: 3,
        p_cost: 1,
        output: hex!("498344ee9d31baf82cc93ebb3874fe0b76e164302c1cefa1b63a90a69afb9b4d"),
    },
    TestVector {
        password: b"\0",
        salt: b"\0",
        s_cost: 3,
        t_cost: 3,
        p_cost: 4,
        output: hex!("8a665611e40710ba1fd78c181549c750f17c12e423c11930ce997f04c7153e0c"),
    },
    TestVector {
        password: b"\0",
        salt: b"\0",
        s_cost: 3,
        t_cost: 3,
        p_cost: 1,
        output: hex!("d9e33c683451b21fb3720afbd78bf12518c1d4401fa39f054b052a145c968bb1"),
    },
    TestVector {
        password: b"password",
        salt: b"salt",
        s_cost: 1,
        t_cost: 1,
        p_cost: 16,
        output: hex!("a67b383bb88a282aef595d98697f90820adf64582a4b3627c76b7da3d8bae915"),
    },
    TestVector {
        password: b"password",
        salt: b"salt",
        s_cost: 1,
        t_cost: 1,
        p_cost: 1,
        output: hex!("97a11df9382a788c781929831d409d3599e0b67ab452ef834718114efdcd1c6d"),
    },
];

#[test]
fn test() {
    for test_vector in TEST_VECTORS {
        let balloon = Balloon::<sha2::Sha256>::new(
            Algorithm::BalloonM,
            Params::new(test_vector.s_cost, test_vector.t_cost, test_vector.p_cost).unwrap(),
            None,
        );

        assert_eq!(
            balloon
                .hash(test_vector.password, test_vector.salt)
                .unwrap()
                .as_slice(),
            test_vector.output,
        );
    }
}
