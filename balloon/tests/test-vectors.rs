#![cfg(feature = "alloc")]

use balloon_hash::{Balloon, Params};

struct TestVector {
    password: &'static [u8],
    salt: &'static [u8],
    s_cost: u32,
    t_cost: u32,
    output: [u8; 32],
}

/// Created and tested here: <https://github.com/khonsulabs/nachonavarro-balloon>.
const TEST_VECTORS: &[TestVector] = &[
    TestVector {
        password: b"hunter42",
        salt: b"examplesalt",
        s_cost: 1024,
        t_cost: 3,
        output: [
            113, 96, 67, 223, 247, 119, 180, 74, 167, 184, 141, 203, 171, 18, 192, 120, 171, 236,
            250, 201, 210, 137, 197, 181, 25, 89, 103, 170, 99, 68, 13, 251,
        ],
    },
    TestVector {
        password: b"",
        salt: b"salt",
        s_cost: 3,
        t_cost: 3,
        output: [
            95, 2, 248, 32, 111, 156, 210, 18, 72, 92, 107, 223, 133, 82, 123, 105, 137, 86, 112,
            26, 208, 133, 33, 6, 249, 75, 148, 238, 148, 87, 115, 120,
        ],
    },
    TestVector {
        password: b"password",
        salt: b"",
        s_cost: 3,
        t_cost: 3,
        output: [
            32, 170, 153, 215, 254, 63, 77, 244, 189, 152, 198, 85, 197, 72, 14, 201, 139, 20, 49,
            7, 163, 49, 253, 73, 29, 237, 168, 133, 196, 214, 166, 204,
        ],
    },
    TestVector {
        password: b"\0",
        salt: b"\0",
        s_cost: 3,
        t_cost: 3,
        output: [
            79, 199, 227, 2, 255, 162, 154, 224, 234, 195, 17, 102, 206, 231, 165, 82, 209, 215,
            17, 53, 244, 224, 218, 102, 72, 111, 182, 138, 116, 155, 115, 164,
        ],
    },
    TestVector {
        password: b"password",
        salt: b"salt",
        s_cost: 1,
        t_cost: 1,
        output: [
            238, 253, 164, 168, 167, 91, 70, 31, 163, 137, 193, 220, 250, 243, 233, 223, 172, 188,
            38, 248, 31, 34, 230, 242, 128, 209, 92, 193, 140, 65, 117, 69,
        ],
    },
];

#[test]
fn test() {
    for test_vector in TEST_VECTORS {
        let balloon = Balloon::<sha2::Sha256>::new(
            Params::new(test_vector.s_cost, test_vector.t_cost, 1).unwrap(),
            None,
        );

        assert_eq!(
            test_vector.output,
            balloon
                .hash(test_vector.password, test_vector.salt)
                .unwrap()
                .as_slice()
        );
    }
}
