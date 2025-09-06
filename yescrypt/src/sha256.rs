#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]

use core::ptr;

pub unsafe fn SHA256_Buf(mut in_0: *const u8, mut len: usize, mut digest: *mut u8) {
    use sha2::Digest;
    use sha2::digest::array::Array;
    let mut ctx = sha2::Sha256::new();
    ctx.update(&*ptr::slice_from_raw_parts(in_0, len));

    // TODO
    #[allow(deprecated)]
    ctx.finalize_into(Array::from_mut_slice(&mut *ptr::slice_from_raw_parts_mut(
        digest, 32,
    )));
}

pub fn HMAC_SHA256_Buf(mut key: &[u8], mut in_0: &[u8], mut digest: &mut [u8; 32]) {
    use hmac::{KeyInit, Mac};

    let mut hmac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
        .expect("key length should always be valid with hmac");

    hmac.update(in_0);

    *digest = hmac.finalize().into_bytes().into();
}

pub fn PBKDF2_SHA256(mut passwd: &[u8], mut salt: &[u8], mut c: u64, mut res: &mut [u8]) {
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(passwd, salt, c as u32, res);
}
