extern crate bcrypt_pbkdf;

use bcrypt_pbkdf::bcrypt_pbkdf_with_memory;
use hex_literal::hex;

#[test]
fn test_openbsd_vectors() {
    struct Test {
        password: &'static str,
        salt: Vec<u8>,
        rounds: u32,
        out: Vec<u8>,
    }

    let tests = vec![
        Test {
            password: "password",
            salt: b"salt".to_vec(),
            rounds: 4,
            out: hex!("5bbf0cc293587f1c3635555c27796598d47e579071bf427e9d8fbe842aba34d9").to_vec(),
        },
        Test {
            password: "password",
            salt: vec![0],
            rounds: 4,
            out: hex!("c12b566235eee04c212598970a579a67").to_vec(),
        },
        Test {
            password: "\x00",
            salt: b"salt".to_vec(),
            rounds: 4,
            out: hex!("6051be18c2f4f82cbf0efee5471b4bb9").to_vec(),
        },
        Test {
            password: "password\x00",
            salt: b"salt\x00".to_vec(),
            rounds: 4,
            out: hex!("7410e44cf4fa07bfaac8a928b1727fac001375e7bf7384370f48efd121743050").to_vec(),
        },
        Test {
            password: "pass\x00wor",
            salt: b"sa\x00l".to_vec(),
            rounds: 4,
            out: hex!("c2bffd9db38f6569efef4372f4de83c0").to_vec(),
        },
        Test {
            password: "pass\x00word",
            salt: b"sa\x00lt".to_vec(),
            rounds: 4,
            out: hex!("4ba4ac3925c0e8d7f0cdb6bb1684a56f").to_vec(),
        },
        Test {
            password: "password",
            salt: b"salt".to_vec(),
            rounds: 8,
            out: hex!(
                "e1367ec5151a33faac4cc1c144cd"
                "23fa15d5548493ecc99b9b5d9c0d"
                "3b27bec76227ea66088b849b20ab"
                "7aa478010246e74bba51723fefa9"
                "f9474d6508845e8d")
            .to_vec(),
        },
        Test {
            password: "password",
            salt: b"salt".to_vec(),
            rounds: 42,
            out: hex!("833cf0dcf56db65608e8f0dc0ce882bd").to_vec(),
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
            salt: b"salis\x00".to_vec(),
            rounds: 8,
            out: hex!("10978b07253df57f71a162eb0e8ad30a").to_vec(),
        },
    ];

    for t in tests.iter() {
        let mut out = vec![0; t.out.len()];
        let mut memory = vec![0; (t.out.len() + 32 - 1) / 32 * 32];
        bcrypt_pbkdf_with_memory(t.password, &t.salt[..], t.rounds, &mut out, &mut memory).unwrap();
        assert_eq!(out, t.out);
    }
}
