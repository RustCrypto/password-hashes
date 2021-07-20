//! Test vectors from R 50.1.111-2016:
//! https://tc26.ru/standard/rs/Р 50.1.111-2016.pdf
use hex_literal::hex;

#[test]
#[rustfmt::skip]
fn gost_test() {
    let pbkdf2 = pbkdf2::pbkdf2::<hmac::Hmac<streebog::Streebog512>>;
    let mut res64 = [0u8; 64];
    let mut res100 = [0u8; 100];

    pbkdf2(b"password", b"salt", 1, &mut res64);
    assert_eq!(
        res64,
        hex!("
            64770af7f748c3b1c9ac831dbcfd85c2
            6111b30a8a657ddc3056b80ca73e040d
            2854fd36811f6d825cc4ab66ec0a68a4
            90a9e5cf5156b3a2b7eecddbf9a16b47
        "),
    );

    pbkdf2(b"password", b"salt", 2, &mut res64);
    assert_eq!(
        res64,
        hex!("
            5a585bafdfbb6e8830d6d68aa3b43ac0
            0d2e4aebce01c9b31c2caed56f0236d4
            d34b2b8fbd2c4e89d54d46f50e47d45b
            bac301571743119e8d3c42ba66d348de
        "),
    );

    pbkdf2(b"password", b"salt", 4096, &mut res64);
    assert_eq!(
        res64,
        hex!("
            e52deb9a2d2aaff4e2ac9d47a41f34c2
            0376591c67807f0477e32549dc341bc7
            867c09841b6d58e29d0347c996301d55
            df0d34e47cf68f4e3c2cdaf1d9ab86c3
        "),
    );

    // this test passes, but takes more than 1 minute to
    // execute in release mode
    /*
    pbkdf2(b"password", b"salt", 16777216, &mut res64);
    assert_eq!(
        res64,
        hex!("
            49e4843bba76e300afe24c4d23dc7392
            def12f2c0e244172367cd70a8982ac36
            1adb601c7e2a314e8cb7b1e9df840e36
            ab5615be5d742b6cf203fb55fdc48071
        "),
    );
    */

    pbkdf2(
        b"passwordPASSWORDpassword",
        b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
        4096,
        &mut res100,
    );
    assert_eq!(
        res100,
        hex!("
            b2d8f1245fc4d29274802057e4b54e0a
            0753aa22fc53760b301cf008679e58fe
            4bee9addcae99ba2b0b20f431a9c5e50
            f395c89387d0945aedeca6eb4015dfc2
            bd2421ee9bb71183ba882ceebfef259f
            33f9e27dc6178cb89dc37428cf9cc52a
            2baa2d3a
        "),
    );

    pbkdf2(b"pass\0word", b"sa\0lt", 4096, &mut res64);
    assert_eq!(
        res64,
        hex!("
            50df062885b69801a3c10248eb0a27ab
            6e522ffeb20c991c660f001475d73a4e
            167f782c18e97e92976d9c1d970831ea
            78ccb879f67068cdac1910740844e830
        "),
    );
}
