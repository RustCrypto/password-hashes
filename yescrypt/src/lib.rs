#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![warn(
    //clippy::cast_lossless,
    //clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    //clippy::cast_sign_loss,
    clippy::checked_conversions,
    clippy::implicit_saturating_sub,
    clippy::panic,
    clippy::panic_in_result_fn,
    //missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]
// Temporary lint overrides while C code is being translated
#![allow(
    clippy::cast_possible_wrap,
    clippy::too_many_arguments,
    clippy::toplevel_ref_arg,
    clippy::unwrap_used,
    unsafe_op_in_unsafe_fn
)]

// Adapted from the yescrypt reference implementation available at:
// <https://github.com/openwall/yescrypt>
//
// Relicensed from the BSD-2-Clause license to Apache 2.0+MIT with permission:
// <https://github.com/openwall/yescrypt/issues/7>

extern crate alloc;

mod common;
mod error;
mod params;
mod salsa20;
mod sha256;

pub use crate::{
    error::{Error, Result},
    params::{Flags, Params},
};

use crate::{
    common::{blkcpy, blkxor, integerify, le32dec, le32enc, prev_power_of_two, wrap},
    sha256::{HMAC_SHA256_Buf, PBKDF2_SHA256, SHA256_Buf},
};
use alloc::{boxed::Box, vec, vec::Vec};
use core::ptr;
use libc::{c_void, free, malloc, memcpy};

#[derive(Clone)]
#[repr(C)]
struct Local {
    pub aligned: Box<[u32]>,
}

#[derive(Copy, Clone)]
#[repr(C)]
struct PwxformCtx {
    pub s: *mut u32,
    pub s0: *mut [u32; 2],
    pub s1: *mut [u32; 2],
    pub s2: *mut [u32; 2],
    pub w: usize,
}

/// yescrypt Key Derivation Function (KDF)
pub fn yescrypt_kdf(passwd: &[u8], salt: &[u8], params: &Params, dst: &mut [u8]) -> Result<()> {
    let mut local = Local {
        aligned: Vec::new().into_boxed_slice(),
    };

    if params.g != 0 {
        return Err(Error(-1));
    }

    if params.flags.contains(Flags::RW)
        && params.p >= 1
        && (params.n / params.p as u64) >= 0x100
        && params.n / (params.p as u64) / (params.r as u64) >= 0x20000
    {
        return Err(Error(-1));
    }

    unsafe {
        yescrypt_kdf_body(
            &mut local,
            passwd.as_ptr(),
            passwd.len(),
            salt.as_ptr(),
            salt.len(),
            params.flags,
            params.n,
            params.r,
            params.p,
            params.t,
            params.nrom,
            dst.as_mut_ptr(),
            dst.len(),
        )
    }
}

unsafe fn yescrypt_kdf_body(
    local: &mut Local,
    mut passwd: *const u8,
    mut passwdlen: usize,
    salt: *const u8,
    saltlen: usize,
    flags: Flags,
    n: u64,
    r: u32,
    p: u32,
    t: u32,
    nrom: u64,
    buf: *mut u8,
    buflen: usize,
) -> Result<()> {
    let mut sha256 = [0u32; 8];
    let mut dk = [0u8; 32];

    match flags.bits() & Flags::MODE_MASK.bits() {
        0 => {
            if !flags.is_empty() || t != 0 || nrom != 0 {
                return Err(Error(-1));
            }
        }
        1 => {
            if flags != Flags::WORM || nrom != 0 {
                return Err(Error(-1));
            }
        }
        2 => {
            if flags
                != flags
                    & (Flags::MODE_MASK
                        | Flags::RW_FLAVOR_MASK
                        | Flags::SHARED_PREALLOCATED
                        | Flags::INIT_SHARED
                        | Flags::ALLOC_ONLY
                        | Flags::PREHASH)
            {
                return Err(Error(-1));
            }

            if (flags & Flags::RW_FLAVOR_MASK)
                != (Flags::ROUNDS_6 | Flags::GATHER_4 | Flags::SIMPLE_2 | Flags::SBOX_12K)
            {
                return Err(Error(-1));
            }
        }
        _ => {
            return Err(Error(-1));
        }
    }
    if !((buflen <= ((1 << 32) - 1) * 32)
        && ((r as u64) * (p as u64) < (1 << 30) as u64)
        && !(n & (n - 1) != 0 || n <= 1 || r < 1 || p < 1)
        && !(r as u64 > u64::MAX / 128 / (p as u64) || n > u64::MAX / 128 / (r as u64))
        && (n <= u64::MAX / ((t as u64) + 1)))
    {
        return Err(Error(-1));
    }

    if flags.contains(Flags::RW)
        && (n / (p as u64) <= 1
            || r < ((4 * 2 * 8 + 127) / 128) as u32
            || p as u64 > u64::MAX / (3 * (1 << 8) * 2 * 8)
            || p as u64 > u64::MAX / (size_of::<PwxformCtx>() as u64))
    {
        return Err(Error(-1));
    }

    if nrom != 0 {
        return Err(Error(-1));
    }

    let mut v_owned: Box<[u32]>;
    let v_size = 32 * (r as usize) * (n as usize);
    let v = if flags.contains(Flags::INIT_SHARED) {
        if local.aligned.len() < v_size {
            // why can't we just reallocate here?
            if !local.aligned.is_empty() {
                return Err(Error(-1));
            }

            local.aligned = vec![0; v_size].into_boxed_slice();
        }
        if flags.contains(Flags::ALLOC_ONLY) {
            return Err(Error(-2));
        }
        &mut *local.aligned
    } else {
        v_owned = vec![0; v_size].into_boxed_slice();
        &mut *v_owned
    };

    let b_size = 32 * (r as usize) * (p as usize);
    let mut b = vec![0u32; b_size].into_boxed_slice();
    let mut xy = vec![0u32; 64 * (r as usize)].into_boxed_slice();

    if !flags.is_empty() {
        HMAC_SHA256_Buf(
            c"yescrypt-prehash".as_ptr() as *const c_void,
            if flags.contains(Flags::PREHASH) {
                16
            } else {
                8
            },
            passwd as *const c_void,
            passwdlen,
            sha256.as_mut_ptr() as *mut u8,
        );
        passwd = sha256.as_mut_ptr() as *mut u8;
        passwdlen = size_of::<[u32; 8]>();
    }

    PBKDF2_SHA256(
        passwd,
        passwdlen,
        salt,
        saltlen,
        1,
        b.as_mut_ptr().cast(),
        b_size * 4,
    );

    if !flags.is_empty() {
        sha256.copy_from_slice(&b[..8]);
    }

    if flags.contains(Flags::RW) {
        let s = malloc((3 * (1 << 8) * 2 * 8) * (p as usize)) as *mut u32;

        if s.is_null() {
            return Err(Error(-1));
        }
        let pwxform_ctx = malloc(size_of::<PwxformCtx>() * (p as usize)) as *mut PwxformCtx;
        if pwxform_ctx.is_null() {
            free(s as *mut c_void);
            return Err(Error(-1));
        }

        for i in 0..p as usize {
            let offset = i * (((3 * (1 << 8) * 2 * 8) as usize) / size_of::<u32>());
            (*pwxform_ctx.add(i)).s = s.add(offset);
        }

        smix(
            b.as_mut_ptr(),
            r as usize,
            n,
            p,
            t,
            flags,
            v.as_mut_ptr(),
            xy.as_mut_ptr(),
            pwxform_ctx,
            sha256.as_mut_ptr() as *mut u8,
        );
        free(pwxform_ctx as *mut c_void);
        free(s as *mut c_void);
    } else {
        for i in 0..p {
            smix(
                b[32usize.wrapping_mul(r as usize).wrapping_mul(i as usize)..].as_mut_ptr(),
                r as usize,
                n,
                1,
                t,
                flags,
                v.as_mut_ptr(),
                xy.as_mut_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
            );
        }
    }

    let mut dkp = buf;

    if !flags.is_empty() && buflen < 32 {
        PBKDF2_SHA256(
            passwd,
            passwdlen,
            b.as_ptr().cast(),
            b_size * 4,
            1,
            dk.as_mut_ptr(),
            32,
        );
        dkp = dk.as_mut_ptr();
    }

    PBKDF2_SHA256(
        passwd,
        passwdlen,
        b.as_ptr().cast(),
        b_size * 4,
        1,
        buf,
        buflen,
    );

    if !flags.is_empty() && !flags.contains(Flags::PREHASH) {
        HMAC_SHA256_Buf(
            dkp as *const c_void,
            32,
            b"Client Key\0" as *const u8 as *const i8 as *const c_void,
            10,
            sha256.as_mut_ptr() as *mut u8,
        );
        let mut clen: usize = buflen;
        if clen > 32 {
            clen = 32;
        }
        SHA256_Buf(
            sha256.as_mut_ptr() as *mut u8 as *const c_void,
            size_of::<[u32; 8]>(),
            dk.as_mut_ptr(),
        );
        memcpy(buf as *mut c_void, dk.as_mut_ptr() as *const c_void, clen);
    }

    Ok(())
}

unsafe fn pwxform(b: *mut u32, ctx: *mut PwxformCtx) {
    let x0 = b as *mut [[u32; 2]; 2];
    let s0 = (*ctx).s0;
    let s1 = (*ctx).s1;
    let s2 = (*ctx).s2;
    let mut w = (*ctx).w;

    for i in 0..6 {
        for j in 0..4 {
            let mut xl: u32 = (*x0.add(j))[0][0];
            let mut xh: u32 = (*x0.add(j))[0][1];
            let p0 = s0.add((xl as usize & (((1 << 8) - 1) * 2 * 8)) / 8);
            let p1 = s1.add((xh as usize & (((1 << 8) - 1) * 2 * 8)) / 8);
            for k in 0..2 {
                let s0 = (((*p0.add(k))[1] as u64) << 32).wrapping_add((*p0.add(k))[0] as u64);
                let s1 = (((*p1.add(k))[1] as u64) << 32).wrapping_add((*p1.add(k))[0] as u64);
                xl = (*x0.add(j))[k][0];
                xh = (*x0.add(j))[k][1];
                let mut x = (xh as u64).wrapping_mul(xl as u64);
                x = x.wrapping_add(s0);
                x ^= s1;
                (*x0.add(j))[k][0] = x as u32;
                (*x0.add(j))[k][1] = (x >> 32) as u32;
                if i != 0 && i != (6 - 1) {
                    (*s2.add(w))[0] = x as u32;
                    (*s2.add(w))[1] = (x >> 32) as u32;
                    w += 1;
                }
            }
        }
    }
    (*ctx).s0 = s2;
    (*ctx).s1 = s0;
    (*ctx).s2 = s1;
    (*ctx).w = w & (((1usize) << 8usize) * 2usize - 1usize);
}

unsafe fn blockmix_pwxform(b: *mut u32, ctx: *mut PwxformCtx, r: usize) {
    let mut x = [0u32; 16];
    let r1 = 128usize.wrapping_mul(r).wrapping_div(4 * 2 * 8);
    blkcpy(
        x.as_mut_ptr(),
        b.add(
            r1.wrapping_sub(1usize)
                .wrapping_mul((4usize * 2 * 8).wrapping_div(size_of::<u32>())),
        ),
        (4usize * 2 * 8).wrapping_div(size_of::<u32>()),
    );
    for i in 0..r1 {
        if r1 > 1 {
            blkxor(
                x.as_mut_ptr(),
                b.add(i.wrapping_mul((4usize * 2 * 8).wrapping_div(size_of::<u32>()))),
                (4usize * 2 * 8).wrapping_div(size_of::<u32>()),
            );
        }
        pwxform(x.as_mut_ptr(), ctx);
        blkcpy(
            b.add(i.wrapping_mul((4usize * 2 * 8).wrapping_div(size_of::<u32>()))),
            x.as_mut_ptr(),
            (4usize * 2 * 8).wrapping_div(size_of::<u32>()),
        );
    }
    let i = r1.wrapping_sub(1).wrapping_mul(4 * 2 * 8).wrapping_div(64);
    salsa20::salsa20_2(b.add(i.wrapping_mul(16)));
    for i in (i + 1)..(2 * r) {
        blkxor(
            b.add(i.wrapping_mul(16usize)),
            b.add(i.wrapping_sub(1usize).wrapping_mul(16usize)),
            16_usize,
        );
        salsa20::salsa20_2(b.add(i.wrapping_mul(16)));
    }
}

unsafe fn smix(
    b: *mut u32,
    r: usize,
    n: u64,
    p: u32,
    t: u32,
    flags: Flags,
    v: *mut u32,
    xy: *mut u32,
    ctx: *mut PwxformCtx,
    passwd: *mut u8,
) {
    let s: usize = 32 * r;
    let mut nchunk = n.wrapping_div(p as u64);
    let mut nloop_all = nchunk;
    if flags.contains(Flags::RW) {
        if t <= 1 {
            if t != 0 {
                nloop_all *= 2;
            }
            nloop_all = nloop_all.div_ceil(3);
        } else {
            nloop_all *= t as u64 - 1;
        }
    } else if t != 0 {
        if t == 1 {
            nloop_all += nloop_all.div_ceil(2)
        }
        nloop_all *= t as u64;
    }
    let mut nloop_rw = 0;
    if flags.contains(Flags::INIT_SHARED) {
        nloop_rw = nloop_all;
    } else if flags.contains(Flags::RW) {
        nloop_rw = nloop_all.wrapping_div(p as u64);
    }
    nchunk &= !1;
    nloop_all += 1;
    nloop_all &= !1;
    nloop_rw += 1;
    nloop_rw &= !1;
    let mut vchunk = 0;
    for i in 0..p as usize {
        let np = if i < p as usize - 1 {
            nchunk
        } else {
            n.wrapping_sub(vchunk)
        };

        let bp = b.add(i.wrapping_mul(s));
        let vp = v.add((vchunk as usize).wrapping_mul(s));

        let mut ctx_i: *mut PwxformCtx = ptr::null_mut();
        if flags.contains(Flags::RW) {
            ctx_i = ctx.add(i);
            smix1(
                bp,
                1,
                3 * (1 << 8) * 2 * 8 / 128,
                Flags::empty(),
                (*ctx_i).s,
                xy,
                ptr::null_mut(),
            );
            (*ctx_i).s2 = (*ctx_i).s as *mut [u32; 2];
            (*ctx_i).s1 = ((*ctx_i).s2).add((1 << 8) * 2);
            (*ctx_i).s0 = ((*ctx_i).s1).add((1 << 8) * 2);
            (*ctx_i).w = 0;
            if i == 0 {
                HMAC_SHA256_Buf(
                    bp.add(s.wrapping_sub(16)) as *const c_void,
                    64,
                    passwd as *const c_void,
                    32,
                    passwd,
                );
            }
        }
        smix1(bp, r, np, flags, vp, xy, ctx_i);
        smix2(bp, r, prev_power_of_two(np), nloop_rw, flags, vp, xy, ctx_i);
        vchunk += nchunk;
    }
    for i in 0..p as usize {
        let bp_0 = b.add(i.wrapping_mul(s));
        smix2(
            bp_0,
            r,
            n,
            nloop_all.wrapping_sub(nloop_rw),
            flags & !Flags::RW,
            v,
            xy,
            if flags.contains(Flags::RW) {
                ctx.add(i)
            } else {
                ptr::null_mut()
            },
        );
    }
}

unsafe fn smix1(
    b: *mut u32,
    r: usize,
    n: u64,
    flags: Flags,
    v: *mut u32,
    xy: *mut u32,
    ctx: *mut PwxformCtx,
) {
    let s = (32usize).wrapping_mul(r);
    let x = xy;
    let y = xy.add(s);
    for k in 0..(2usize).wrapping_mul(r) {
        for i in 0..16usize {
            *x.add(k.wrapping_mul(16usize).wrapping_add(i)) = le32dec(
                b.add(
                    k.wrapping_mul(16usize)
                        .wrapping_add(i.wrapping_mul(5usize).wrapping_rem(16usize)),
                ),
            );
        }
    }
    for i in 0..n {
        blkcpy(v.add(usize::try_from(i).unwrap().wrapping_mul(s)), x, s);
        if flags.contains(Flags::RW) && i > 1 {
            let j = wrap(integerify(x, r), i);
            blkxor(x, v.add(usize::try_from(j).unwrap().wrapping_mul(s)), s);
        }
        if !ctx.is_null() {
            blockmix_pwxform(x, ctx, r);
        } else {
            salsa20::blockmix_salsa8(x, y, r);
        }
    }
    for k in 0..(2usize).wrapping_mul(r) {
        for i in 0..16usize {
            le32enc(
                b.add(
                    k.wrapping_mul(16usize)
                        .wrapping_add(i.wrapping_mul(5usize).wrapping_rem(16usize)),
                ),
                *x.add(k.wrapping_mul(16usize).wrapping_add(i)),
            );
        }
    }
}

unsafe fn smix2(
    b: *mut u32,
    r: usize,
    n: u64,
    nloop: u64,
    flags: Flags,
    v: *mut u32,
    xy: *mut u32,
    ctx: *mut PwxformCtx,
) {
    let s = (32usize).wrapping_mul(r);
    let x = xy;
    let y = xy.add(s);
    for k in 0..(2usize).wrapping_mul(r) {
        for i in 0..16usize {
            *x.add(k.wrapping_mul(16usize).wrapping_add(i)) = le32dec(
                b.add(
                    k.wrapping_mul(16usize)
                        .wrapping_add(i.wrapping_mul(5usize).wrapping_rem(16usize)),
                ),
            );
        }
    }
    for _ in 0..nloop {
        {
            let j = integerify(x, r) & n.wrapping_sub(1);
            blkxor(x, v.add(usize::try_from(j).unwrap().wrapping_mul(s)), s);
            if flags.contains(Flags::RW) {
                blkcpy(v.add(usize::try_from(j).unwrap().wrapping_mul(s)), x, s);
            }
        }
        if !ctx.is_null() {
            blockmix_pwxform(x, ctx, r);
        } else {
            salsa20::blockmix_salsa8(x, y, r);
        }
    }
    for k in 0..(2usize).wrapping_mul(r) {
        for i in 0..16usize {
            le32enc(
                b.add(
                    k.wrapping_mul(16)
                        .wrapping_add(i.wrapping_mul(5).wrapping_rem(16)),
                ),
                *x.add(k.wrapping_mul(16).wrapping_add(i)),
            );
        }
    }
}
