#![no_main]
use libfuzzer_sys::arbitrary::{Arbitrary, Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use scrypt::password_hash::{CustomizedPasswordHasher, PasswordVerifier};
use scrypt::phc::PasswordHash;
use scrypt::{scrypt, Params, Scrypt};

#[derive(Debug)]
pub struct ScryptRandParams(pub Params);

impl<'a> Arbitrary<'a> for ScryptRandParams {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let log_n = u.int_in_range(0..=15)?;
        let r = u.int_in_range(1..=16)?;
        let p = u.int_in_range(1..=8)?;
        let len = u.int_in_range(10..=64)?;

        let params = Params::new_with_output_len(log_n, r, p, len).unwrap();
        Ok(Self(params))
    }
}

fuzz_target!(|data: (&[u8], &[u8], ScryptRandParams)| {
    let (password, salt, ScryptRandParams(params)) = data;

    if password.len() > 64 || salt.len() < 8 || salt.len() > 64 {
        return;
    }

    // Check direct hashing
    let mut result = [0u8; 64];
    scrypt(password, salt, &params, &mut result).unwrap();

    // Check PHC hashing
    let hasher = Scrypt::new_with_params(params);
    if let Ok(phc_hash) = hasher.hash_password_customized(password, salt, Some("scrypt"), None, params) {
        let phc_string = phc_hash.to_string();

        // Check PHC verification
        if let Ok(hash) = PasswordHash::new(&phc_string) {
            hasher.verify_password(password, &hash).unwrap();
        }
    }
});
