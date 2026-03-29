use hex_literal::hex;

pub struct BalloonTestVector {
    pub password: &'static [u8],
    pub salt: &'static [u8],
    pub s_cost: u32,
    pub t_cost: u32,
    pub output: [u8; 32],
}

/// Tested with the following implementations:
/// - <https://github.com/nachonavarro/balloon-hashing>
/// - <https://github.com/nogoegst/balloon>
pub const BALLOON_TEST_VECTORS: &[BalloonTestVector] = &[
    BalloonTestVector {
        password: b"hunter42",
        salt: b"examplesalt",
        s_cost: 1024,
        t_cost: 3,
        output: hex!("716043dff777b44aa7b88dcbab12c078abecfac9d289c5b5195967aa63440dfb"),
    },
    BalloonTestVector {
        password: b"",
        salt: b"salt",
        s_cost: 3,
        t_cost: 3,
        output: hex!("5f02f8206f9cd212485c6bdf85527b698956701ad0852106f94b94ee94577378"),
    },
    BalloonTestVector {
        password: b"password",
        salt: b"",
        s_cost: 3,
        t_cost: 3,
        output: hex!("20aa99d7fe3f4df4bd98c655c5480ec98b143107a331fd491deda885c4d6a6cc"),
    },
    BalloonTestVector {
        password: b"\0",
        salt: b"\0",
        s_cost: 3,
        t_cost: 3,
        output: hex!("4fc7e302ffa29ae0eac31166cee7a552d1d71135f4e0da66486fb68a749b73a4"),
    },
    BalloonTestVector {
        password: b"password",
        salt: b"salt",
        s_cost: 1,
        t_cost: 1,
        output: hex!("eefda4a8a75b461fa389c1dcfaf3e9dfacbc26f81f22e6f280d15cc18c417545"),
    },
];
