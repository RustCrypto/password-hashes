#![no_main]
use libfuzzer_sys::fuzz_target;
use scrypt::scrypt;

use fuzz::ScryptRandParams;

fuzz_target!(|data: (&[u8], &[u8], ScryptRandParams)| {
    let (password, salt, ScryptRandParams(params)) = data;
    let mut result = [0u8; 64];
    let res = scrypt(password, salt, &params, &mut result);
    assert!(res.is_ok());
});
