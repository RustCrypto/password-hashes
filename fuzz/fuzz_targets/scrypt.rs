#![no_main]
use libfuzzer_sys::arbitrary::{Arbitrary, Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use scrypt::password_hash::{
    Ident, PasswordHash, PasswordHasher, PasswordVerifier, Salt, SaltString,
};
use scrypt::{scrypt, Scrypt};

#[derive(Debug)]
pub struct ScryptRandParams(pub scrypt::Params);

impl<'a> Arbitrary<'a> for ScryptRandParams {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let log_n = u.int_in_range(0..=15)?;
        let r = u.int_in_range(1..=32)?;
        let p = u.int_in_range(1..=16)?;
        let len = u.int_in_range(10..=64)?;

        let params = scrypt::Params::new(log_n, r, p, len).unwrap();
        Ok(Self(params))
    }
}

fuzz_target!(|data: (&[u8], &[u8], ScryptRandParams)| {
    let (password, salt, ScryptRandParams(params)) = data;

    if password.len() > 64 {
        return;
    }

    if salt.len() < Salt::MIN_LENGTH || salt.len() > (6 * Salt::MAX_LENGTH) / 8 {
        return;
    }

    // Check direct hashing
    let mut result = [0u8; 64];
    scrypt(password, salt, &params, &mut result).unwrap();

    // Check PHC hashing
    let salt_string = SaltString::encode_b64(salt).unwrap();
    let phc_hash = Scrypt
        .hash_password_customized(
            password,
            Some(Ident::new_unwrap("scrypt")),
            None,
            params,
            &salt_string,
        )
        .unwrap()
        .to_string();

    // Check PHC verification
    let hash = PasswordHash::new(&phc_hash).unwrap();
    Scrypt.verify_password(password, &hash).unwrap();
});
