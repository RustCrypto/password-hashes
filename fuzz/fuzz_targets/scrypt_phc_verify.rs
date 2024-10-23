#![no_main]
use libfuzzer_sys::fuzz_target;
use scrypt::password_hash::{PasswordHash, PasswordVerifier};
use scrypt::Scrypt;

const SAMPLE_HASH: &str = "$scrypt$ln=16,r=8,p=1$\
    aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";

fuzz_target!(|password: &[u8]| {
    let hash = PasswordHash::new(SAMPLE_HASH).expect("SAMPLE_HASH is valid");
    let res = Scrypt.verify_password(password, &hash);
    assert!(res.is_err());
});
