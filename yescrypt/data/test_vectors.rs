use hex_literal::hex;
use yescrypt::{Mode, Params};

pub struct TestVector {
    pub password: &'static [u8],
    pub salt: &'static [u8],
    pub mode: Mode,
    pub n: u64,
    pub r: u32,
    pub p: u32,
    pub t: u32,
    pub g: u32,
    pub output: &'static [u8],
}

impl TestVector {
    pub fn params(&self) -> Params {
        Params::new_with_all_params(self.mode, self.n, self.r, self.p, self.t, self.g).unwrap()
    }
}

/// Adapted from the reference implementation's `TESTS-OK`.
/// <https://github.com/openwall/yescrypt/blob/e5873f8/TESTS-OK>
pub static TEST_VECTORS: &[TestVector] = &[
    TestVector {
        password: b"",
        salt: b"",
        mode: Mode::Classic,
        n: 16,
        r: 1,
        p: 1,
        t: 0,
        g: 0,
        output: &hex!(
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
            "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
        ),
    },
    TestVector {
        password: b"",
        salt: b"",
        mode: Mode::Classic,
        n: 16,
        r: 1,
        p: 1,
        t: 0,
        g: 0,
        output: &hex!("77d6576238657b20"),
    },
    TestVector {
        password: b"",
        salt: b"",
        mode: Mode::Classic,
        n: 4,
        r: 1,
        p: 1,
        t: 0,
        g: 0,
        output: &hex!(
            "efad0c23314cb572bc3cfb1543da42f8a8b073004c866b64ab5055a4f09fa5f5"
            "71142ebfe7e05a3b92c432f31dea95ad5f9c854b6456462f4bd0f732b7cdc549"
        ),
    },
    TestVector {
        password: b"",
        salt: b"",
        mode: Mode::Worm,
        n: 4,
        r: 1,
        p: 1,
        t: 0,
        g: 0,
        output: &hex!(
            "85dda48c9ec9de2f7f1ae8b4dfeda51f8b6d56f3081be1a7c0833ba2719a36ab"
            "02885dae36557d342686b17ba75f2c217792de0970ab1d07a9c750936d31426f"
        ),
    },
    TestVector {
        password: b"",
        salt: b"",
        mode: Mode::Worm,
        n: 4,
        r: 1,
        p: 1,
        t: 0,
        g: 0,
        output: &hex!("85dda48c9ec9de2f"),
    },
    TestVector {
        password: b"",
        salt: b"",
        mode: Mode::Worm,
        n: 4,
        r: 1,
        p: 1,
        t: 1,
        g: 0,
        output: &hex!(
            "4baa8cd8608ba91f3e3439d9ec4fae8f9fc092d9ca22b7377e31ae5b9ad7877c"
            "1168691162dd0e5ef049e570650cbed4384ad60534fb0cbed19ff3f033c94b0c"
        ),
    },
    TestVector {
        password: b"",
        salt: b"",
        mode: Mode::Worm,
        n: 4,
        r: 1,
        p: 1,
        t: 2,
        g: 0,
        output: &hex!(
            "e6e8bba09b6412ffb0b3cc35e37d0b782a47fbaadc57a076d7c6cc2e70919a1b"
            "8d4738c4f83355690742d9bed71c3b8fb0d7eb086ab134c5e55707c2c13c75ef"
        ),
    },
    TestVector {
        password: b"",
        salt: b"",
        mode: Mode::Worm,
        n: 4,
        r: 1,
        p: 1,
        t: 3,
        g: 0,
        output: &hex!(
            "acd9a4201cf4a476ecf7baa6113d86fb65cd07102b4004e4f9d99cd34255a108"
            "997d70ae0a64bf0a4d96c173abf88279c1a94ad9bdf168edfbbd90f66ed5c80d"
        ),
    },
    TestVector {
        password: b"",
        salt: b"",
        mode: Mode::Worm,
        n: 4,
        r: 1,
        p: 1,
        t: 3,
        g: 0,
        output: &hex!("acd9a4201cf4a476ecf7baa6113d86fb65cd07102b4004e4f9d99cd34255a10899"),
    },
    TestVector {
        password: b"",
        salt: b"",
        mode: Mode::Worm,
        n: 4,
        r: 1,
        p: 1,
        t: 3,
        g: 0,
        output: &hex!("acd9a4201cf4a476ecf7baa6113d86fb65cd07102b4004e4f9d99cd34255a108"),
    },
    TestVector {
        password: b"",
        salt: b"",
        mode: Mode::Worm,
        n: 4,
        r: 1,
        p: 1,
        t: 3,
        g: 0,
        output: &hex!("acd9a4201cf4a476ecf7baa6113d86fb65cd07102b4004e4f9d99cd34255a1"),
    },
    TestVector {
        password: b"",
        salt: b"",
        mode: Mode::Worm,
        n: 4,
        r: 1,
        p: 1,
        t: 3,
        g: 0,
        output: &hex!("ac"),
    },
    TestVector {
        password: b"",
        salt: b"",
        mode: Mode::Rw,
        n: 4,
        r: 1,
        p: 1,
        t: 0,
        g: 0,
        output: &hex!(
            "0cd5af76eb241df8119a9a122ae36920bcc7f414b9c0d58f45008060dade46b0"
            "c80922bdcc16a3ab5d201d4c6140c671be1f75272ca904739d5ad1ff672b0c21"
        ),
    },
    TestVector {
        password: b"",
        salt: b"",
        mode: Mode::Rw,
        n: 4,
        r: 1,
        p: 1,
        t: 0,
        g: 0,
        output: &hex!("0cd5af76"),
    },
    TestVector {
        password: b"",
        salt: b"",
        mode: Mode::Rw,
        n: 4,
        r: 1,
        p: 1,
        t: 1,
        g: 0,
        output: &hex!(
            "23b6adf0b60c9a997f58583d80cda48c638cdc2f289edf93a70807725a0d35c4"
            "68ca362c5557cc04b6811e2e730841f526d8f4f7acfbfa9e06fe1f383a71155e"
        ),
    },
    TestVector {
        password: b"",
        salt: b"",
        mode: Mode::Rw,
        n: 4,
        r: 1,
        p: 1,
        t: 1,
        g: 0,
        output: &hex!("23b6adf0b60c9a997f58583d80cda48c638cdc2f289edf93a70807725a0d35c468"),
    },
    TestVector {
        password: b"",
        salt: b"",
        mode: Mode::Rw,
        n: 4,
        r: 1,
        p: 1,
        t: 1,
        g: 0,
        output: &hex!("23b6adf0b60c9a997f58583d80cda48c638cdc2f289edf93a70807725a0d35c4"),
    },
    TestVector {
        password: b"",
        salt: b"",
        mode: Mode::Rw,
        n: 4,
        r: 1,
        p: 1,
        t: 1,
        g: 0,
        output: &hex!("23b6adf0b60c9a997f58583d80cda48c638cdc2f289edf93a70807725a0d35"),
    },
    TestVector {
        password: b"",
        salt: b"",
        mode: Mode::Rw,
        n: 4,
        r: 1,
        p: 1,
        t: 1,
        g: 0,
        output: &hex!("23"),
    },
    TestVector {
        password: b"p",
        salt: b"s",
        mode: Mode::Rw,
        n: 16,
        r: 8,
        p: 1,
        t: 10,
        g: 0,
        output: &hex!(
            "e1f981733a94052fcd7acb1405df0bbde8e499b6a1331b775909b48c2f516c40dcc8301635b7237b"
        ),
    },
    TestVector {
        password: b"p",
        salt: b"s",
        mode: Mode::Worm,
        n: 16,
        r: 8,
        p: 1,
        t: 10,
        g: 0,
        output: &hex!(
            "9e7a4097644284cf3b73b60450ff230cdcb6b1b19b1509eeb482f696c4f1c705c00f740216183a12"
        ),
    },
    TestVector {
        password: b"p",
        salt: b"s",
        mode: Mode::Rw,
        n: 16,
        r: 8,
        p: 1,
        t: 0,
        g: 0,
        output: &hex!(
            "c8c7ff1122b0b291c3f2608948782cd689cc45579017aaa5ff8baa74a632ec99c3d66930fb2023bb"
        ),
    },
    TestVector {
        password: b"p",
        salt: b"s",
        mode: Mode::Worm,
        n: 16,
        r: 8,
        p: 1,
        t: 0,
        g: 0,
        output: &hex!(
            "9dd636c2d0bb92345286efdaf8a68cfc1b4ffdc4b1adaccc7d864b9a6787b85d6ae0f5280da8889f"
        ),
    },
    TestVector {
        password: b"p",
        salt: b"s",
        mode: Mode::Rw,
        n: 16,
        r: 8,
        p: 1,
        t: 0,
        g: 0,
        output: &hex!("c8c7ff1122b0b291c3f2608948782cd689cc45579017aaa5ff8baa74a632ec99"),
    },
    TestVector {
        password: b"p",
        salt: b"s",
        mode: Mode::Rw,
        n: 16,
        r: 8,
        p: 1,
        t: 0,
        g: 0,
        output: &hex!("c8c7ff1122b0b291"),
    },
];
