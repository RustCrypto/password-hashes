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

pub unsafe fn HMAC_SHA256_Buf(
    mut K: *const u8,
    mut Klen: usize,
    mut in_0: *const u8,
    mut len: usize,
    mut digest: *mut u8,
) {
    use hmac::{KeyInit, Mac};

    let key = &*ptr::slice_from_raw_parts(K, Klen);

    let mut hmac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
        .expect("key length should always be valid with hmac");

    let mut in_0 = in_0;
    let mut len = len;
    hmac.update(&*ptr::slice_from_raw_parts(in_0, len));

    let mac = hmac.finalize().into_bytes();
    ptr::copy_nonoverlapping(mac.as_ptr() as *const _, digest as *mut _, 32);
}

pub unsafe fn PBKDF2_SHA256(
    mut passwd: *const u8,
    mut passwdlen: usize,
    mut salt: *const u8,
    mut saltlen: usize,
    mut c: u64,
    mut buf: *mut u8,
    mut dkLen: usize,
) {
    let passwd = ptr::slice_from_raw_parts(passwd, passwdlen);
    let salt = ptr::slice_from_raw_parts(salt, saltlen);
    let res = ptr::slice_from_raw_parts_mut(buf, dkLen);

    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(&*passwd, &*salt, c as u32, &mut *res);
}
