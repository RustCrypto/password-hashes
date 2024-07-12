#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]

use crate::{size_t, uint32_t, uint64_t, uint8_t};
use libc::memcpy;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct SHA256_CTX {
    pub state: [uint32_t; 8],
    pub count: uint64_t,
    pub buf: [uint8_t; 64],
}

#[derive(Clone)]
#[repr(C)]
pub struct HMAC_SHA256_CTX {
    hmac: hmac::Hmac<sha2::Sha256>,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub tmp8: [uint8_t; 96],
    pub state: [uint32_t; 8],
}

#[inline]
unsafe fn be32dec(mut pp: *const libc::c_void) -> uint32_t {
    let mut p: *const uint8_t = pp as *const uint8_t;
    return (*p.offset(3 as libc::c_int as isize) as uint32_t)
        .wrapping_add((*p.offset(2 as libc::c_int as isize) as uint32_t) << 8 as libc::c_int)
        .wrapping_add((*p.offset(1 as libc::c_int as isize) as uint32_t) << 16 as libc::c_int)
        .wrapping_add((*p.offset(0 as libc::c_int as isize) as uint32_t) << 24 as libc::c_int);
}

#[inline]
unsafe fn be32enc(mut pp: *mut libc::c_void, mut x: uint32_t) {
    let mut p: *mut uint8_t = pp as *mut uint8_t;
    *p.offset(3 as libc::c_int as isize) = (x & 0xff as libc::c_int as libc::c_uint) as uint8_t;
    *p.offset(2 as libc::c_int as isize) =
        (x >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as uint8_t;
    *p.offset(1 as libc::c_int as isize) =
        (x >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as uint8_t;
    *p.offset(0 as libc::c_int as isize) =
        (x >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as uint8_t;
}

#[inline]
unsafe fn be64enc(mut pp: *mut libc::c_void, mut x: uint64_t) {
    let mut p: *mut uint8_t = pp as *mut uint8_t;
    *p.offset(7 as libc::c_int as isize) = (x & 0xff as libc::c_int as libc::c_ulong) as uint8_t;
    *p.offset(6 as libc::c_int as isize) =
        (x >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as uint8_t;
    *p.offset(5 as libc::c_int as isize) =
        (x >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as uint8_t;
    *p.offset(4 as libc::c_int as isize) =
        (x >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as uint8_t;
    *p.offset(3 as libc::c_int as isize) =
        (x >> 32 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as uint8_t;
    *p.offset(2 as libc::c_int as isize) =
        (x >> 40 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as uint8_t;
    *p.offset(1 as libc::c_int as isize) =
        (x >> 48 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as uint8_t;
    *p.offset(0 as libc::c_int as isize) =
        (x >> 56 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as uint8_t;
}

unsafe fn be32enc_vect(mut dst: *mut uint8_t, mut src: *const uint32_t, mut len: size_t) {
    loop {
        be32enc(
            &mut *dst.offset(0 as libc::c_int as isize) as *mut uint8_t as *mut libc::c_void,
            *src.offset(0 as libc::c_int as isize),
        );
        be32enc(
            &mut *dst.offset(4 as libc::c_int as isize) as *mut uint8_t as *mut libc::c_void,
            *src.offset(1 as libc::c_int as isize),
        );
        src = src.offset(2 as libc::c_int as isize);
        dst = dst.offset(8 as libc::c_int as isize);
        len = len.wrapping_sub(1);
        if !(len != 0) {
            break;
        }
    }
}

unsafe fn be32dec_vect(mut dst: *mut uint32_t, mut src: *const uint8_t, mut len: size_t) {
    loop {
        *dst.offset(0 as libc::c_int as isize) = be32dec(&*src.offset(0 as libc::c_int as isize)
            as *const uint8_t
            as *const libc::c_void);
        *dst.offset(1 as libc::c_int as isize) = be32dec(&*src.offset(4 as libc::c_int as isize)
            as *const uint8_t
            as *const libc::c_void);
        src = src.offset(8 as libc::c_int as isize);
        dst = dst.offset(2 as libc::c_int as isize);
        len = len.wrapping_sub(1);
        if !(len != 0) {
            break;
        }
    }
}

pub unsafe fn SHA256_Buf(mut in_0: *const libc::c_void, mut len: size_t, mut digest: *mut uint8_t) {
    use sha2::digest::array::Array;
    use sha2::Digest;
    let mut ctx = sha2::Sha256::new();
    ctx.update(&*core::ptr::slice_from_raw_parts(
        in_0 as *const u8,
        len as usize,
    ));
    ctx.finalize_into(Array::from_mut_slice(
        &mut *core::ptr::slice_from_raw_parts_mut(digest, 32),
    ));
}

unsafe fn _HMAC_SHA256_Init(
    // mut ctx: *mut HMAC_SHA256_CTX,
    mut _K: *const libc::c_void,
    mut Klen: size_t,
) -> HMAC_SHA256_CTX {
    let mut K: *const uint8_t = _K as *const uint8_t;
    let key = &*core::ptr::slice_from_raw_parts(K, Klen as usize);
    use hmac::KeyInit;
    let hmac = hmac::Hmac::new_from_slice(key).unwrap();
    HMAC_SHA256_CTX { hmac }
}

unsafe fn _HMAC_SHA256_Update(
    ctx: &mut HMAC_SHA256_CTX,
    mut in_0: *const libc::c_void,
    mut len: size_t,
) {
    use hmac::Mac;
    ctx.hmac.update(&*core::ptr::slice_from_raw_parts(
        in_0 as *const u8,
        len as usize,
    ));
}

unsafe fn _HMAC_SHA256_Final(mut digest: *mut uint8_t, mut ctx: HMAC_SHA256_CTX) {
    use hmac::Mac;
    let mac = ctx.hmac.finalize().into_bytes();
    memcpy(digest as *mut _, mac.as_ptr() as *const _, 32);
}

pub unsafe fn HMAC_SHA256_Buf(
    mut K: *const libc::c_void,
    mut Klen: size_t,
    mut in_0: *const libc::c_void,
    mut len: size_t,
    mut digest: *mut uint8_t,
) {
    let mut ctx = _HMAC_SHA256_Init(K, Klen);
    _HMAC_SHA256_Update(&mut ctx, in_0, len);
    _HMAC_SHA256_Final(digest, ctx);
}

pub unsafe fn PBKDF2_SHA256(
    mut passwd: *const uint8_t,
    mut passwdlen: size_t,
    mut salt: *const uint8_t,
    mut saltlen: size_t,
    mut c: uint64_t,
    mut buf: *mut uint8_t,
    mut dkLen: size_t,
) {
    let passwd = core::ptr::slice_from_raw_parts(passwd, passwdlen as usize);
    let salt = core::ptr::slice_from_raw_parts(salt, saltlen as usize);
    let res = core::ptr::slice_from_raw_parts_mut(buf, dkLen as usize);

    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(&*passwd, &*salt, c as u32, &mut *res);
}
