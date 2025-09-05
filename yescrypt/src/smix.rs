//! Core sequential memory-hard mixing function, inherited from the scrypt key derivation function.

use crate::{
    Flags, PwxformCtx, blockmix_pwxform,
    common::{blkcpy, blkxor, integerify, le32dec, le32enc, prev_power_of_two, wrap},
    sha256::HMAC_SHA256_Buf,
};
use core::ffi::c_void;
use core::ptr;

pub(crate) unsafe fn smix(
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
            crate::salsa20::blockmix_salsa8(x, y, r);
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
            crate::salsa20::blockmix_salsa8(x, y, r);
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
