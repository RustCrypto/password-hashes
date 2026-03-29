use hex_literal::hex;

pub struct Test {
    pub password: &'static str,
    pub salt: &'static [u8],
    pub rounds: u32,
    pub out: &'static [u8],
}

pub static TEST_VECTORS: &[Test] = &[
    Test {
        password: "password",
        salt: b"salt",
        rounds: 4,
        out: &hex!("5bbf0cc293587f1c3635555c27796598d47e579071bf427e9d8fbe842aba34d9"),
    },
    Test {
        password: "password",
        salt: &[0],
        rounds: 4,
        out: &hex!("c12b566235eee04c212598970a579a67"),
    },
    Test {
        password: "\x00",
        salt: b"salt",
        rounds: 4,
        out: &hex!("6051be18c2f4f82cbf0efee5471b4bb9"),
    },
    Test {
        password: "password\x00",
        salt: b"salt\x00",
        rounds: 4,
        out: &hex!("7410e44cf4fa07bfaac8a928b1727fac001375e7bf7384370f48efd121743050"),
    },
    Test {
        password: "pass\x00wor",
        salt: b"sa\x00l",
        rounds: 4,
        out: &hex!("c2bffd9db38f6569efef4372f4de83c0"),
    },
    Test {
        password: "pass\x00word",
        salt: b"sa\x00lt",
        rounds: 4,
        out: &hex!("4ba4ac3925c0e8d7f0cdb6bb1684a56f"),
    },
    Test {
        password: "password",
        salt: b"salt",
        rounds: 8,
        out: &hex!(
                "e1367ec5151a33faac4cc1c144cd"
                "23fa15d5548493ecc99b9b5d9c0d"
                "3b27bec76227ea66088b849b20ab"
                "7aa478010246e74bba51723fefa9"
                "f9474d6508845e8d"),
    },
    Test {
        password: "password",
        salt: b"salt",
        rounds: 42,
        out: &hex!("833cf0dcf56db65608e8f0dc0ce882bd"),
    },
    Test {
        password: concat!(
            "Lorem ipsum dolor sit amet, consectetur adipisicing elit, ",
            "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ",
            "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris ",
            "nisi ut aliquip ex ea commodo consequat. ",
            "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum ",
            "dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non ",
            "proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
        ),
        salt: b"salis\x00",
        rounds: 8,
        out: &hex!("10978b07253df57f71a162eb0e8ad30a"),
    },
];
