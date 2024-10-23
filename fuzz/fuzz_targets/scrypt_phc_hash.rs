#![no_main]
use libfuzzer_sys::fuzz_target;
use scrypt::password_hash::{Ident, PasswordHasher, Salt, SaltString};
use scrypt::Scrypt;

use fuzz::ScryptRandParams;

fuzz_target!(|data: (&[u8], &[u8], ScryptRandParams)| {
    let (password, salt, ScryptRandParams(params)) = data;
    if salt.len() < Salt::MIN_LENGTH {
        return;
    }
    let salt_string = SaltString::encode_b64(salt).unwrap();
    let res = Scrypt.hash_password_customized(
        password,
        Some(Ident::new_unwrap("scrypt")),
        None,
        params,
        &salt_string,
    );
    assert!(res.is_ok());
});
