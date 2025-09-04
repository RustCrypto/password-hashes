#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]

use libc::memcpy;

pub unsafe fn SHA256_Buf(mut in_0: *const libc::c_void, mut len: usize, mut digest: *mut u8) {
    use sha2::Digest;
    use sha2::digest::array::Array;
    let mut ctx = sha2::Sha256::new();
    ctx.update(&*core::ptr::slice_from_raw_parts(in_0 as *const u8, len));

    // TODO
    #[allow(deprecated)]
    ctx.finalize_into(Array::from_mut_slice(
        &mut *core::ptr::slice_from_raw_parts_mut(digest, 32),
    ));
}

pub unsafe fn HMAC_SHA256_Buf(
    mut K: *const libc::c_void,
    mut Klen: usize,
    mut in_0: *const libc::c_void,
    mut len: usize,
    mut digest: *mut u8,
) {
    use hmac::KeyInit;
    use hmac::Mac;

    let key = &*core::ptr::slice_from_raw_parts(K as *const u8, Klen);

    let mut hmac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
        .expect("key length should always be valid with hmac");

    let mut in_0 = in_0;
    let mut len = len;
    hmac.update(&*core::ptr::slice_from_raw_parts(in_0 as *const u8, len));

    let mac = hmac.finalize().into_bytes();
    memcpy(digest as *mut _, mac.as_ptr() as *const _, 32);
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
    let passwd = core::ptr::slice_from_raw_parts(passwd, passwdlen);
    let salt = core::ptr::slice_from_raw_parts(salt, saltlen);
    let res = core::ptr::slice_from_raw_parts_mut(buf, dkLen);

    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(&*passwd, &*salt, c as u32, &mut *res);
}
