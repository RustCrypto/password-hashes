//! pwxform: parallel wide transformation

use crate::{
    Flags,
    common::{blkcpy, blkxor, integerify, le32dec, le32enc, prev_power_of_two, wrap},
    salsa20,
    sha256::HMAC_SHA256_Buf,
};
use core::{ffi::c_void, ptr};

/// Parallel wide transformation (pwxform) context.
#[derive(Copy, Clone)]
#[repr(C)]
pub(crate) struct PwxformCtx {
    pub s: *mut u32,
    pub s0: *mut [u32; 2],
    pub s1: *mut [u32; 2],
    pub s2: *mut [u32; 2],
    pub w: usize,
}

/// Compute `B = SMix_r(B, N)`.
///
/// The input B must be 128rp bytes in length; the temporary storage V must be 128rN bytes in
/// length; the temporary storage XY must be 256r bytes in length.  The value N must be a power of 2
/// greater than 1.
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

    // 1: n <-- N / p
    let mut nchunk = n / (p as u64);

    // 2: Nloop_all <-- fNloop(n, t, flags)
    let mut nloop_all = nchunk;
    if flags.contains(Flags::RW) {
        if t <= 1 {
            if t != 0 {
                nloop_all *= 2; // 2/3
            }
            nloop_all = nloop_all.div_ceil(3); // 1/3, round up
        } else {
            nloop_all *= t as u64 - 1;
        }
    } else if t != 0 {
        if t == 1 {
            nloop_all += nloop_all.div_ceil(2) // 1.5, round up
        }
        nloop_all *= t as u64;
    }

    // 6: Nloop_rw <-- 0
    let mut nloop_rw = 0;
    if flags.contains(Flags::INIT_SHARED) {
        nloop_rw = nloop_all;
    } else if flags.contains(Flags::RW) {
        // 4: Nloop_rw <-- Nloop_all / p
        nloop_rw = nloop_all / (p as u64);
    }

    // 8: n <-- n - (n mod 2)
    nchunk &= !1; // round down to even

    // 9: Nloop_all <-- Nloop_all + (Nloop_all mod 2)
    nloop_all += 1;
    nloop_all &= !1; // round up to even

    // 10: Nloop_rw <-- Nloop_rw + (Nloop_rw mod 2)
    nloop_rw += 1;
    nloop_rw &= !1; // round up to even
    let mut vchunk = 0;

    // 11: for i = 0 to p - 1 do
    // 12: u <-- in
    for i in 0..p as usize {
        // 13: if i = p - 1
        // 14:   n <-- N - u
        // 15: end if
        // 16: v <-- u + n - 1
        let np = if i < p as usize - 1 {
            nchunk
        } else {
            n.wrapping_sub(vchunk)
        };
        let bp = b.add(i.wrapping_mul(s));
        let vp = v.add((vchunk as usize).wrapping_mul(s));
        let mut ctx_i: *mut PwxformCtx = ptr::null_mut();

        // 17: if YESCRYPT_RW flag is set
        if flags.contains(Flags::RW) {
            ctx_i = ctx.add(i);

            // 18: SMix1_1(B_i, Sbytes / 128, S_i, no flags)
            smix1(
                bp,
                1,
                3 * (1 << 8) * 2 * 8 / 128,
                Flags::empty(),
                (*ctx_i).s,
                xy,
                ptr::null_mut(),
            );

            // 19: S2_i <-- S_{i,0...2^Swidth-1}
            (*ctx_i).s2 = (*ctx_i).s as *mut [u32; 2];

            // 20: S1_i <-- S_{i,2^Swidth...2*2^Swidth-1}
            (*ctx_i).s1 = ((*ctx_i).s2).add((1 << 8) * 2);

            // 21: S0_i <-- S_{i,2*2^Swidth...3*2^Swidth-1}
            (*ctx_i).s0 = ((*ctx_i).s1).add((1 << 8) * 2);

            // 22: w_i <-- 0
            (*ctx_i).w = 0;

            // 23: if i = 0
            if i == 0 {
                // 24: passwd <-- HMAC-SHA256(B_{0,2r-1}, passwd)
                HMAC_SHA256_Buf(
                    bp.add(s.wrapping_sub(16)) as *const c_void,
                    64,
                    passwd as *const c_void,
                    32,
                    passwd,
                );
            }
        }

        // 27: SMix1_r(B_i, n, V_{u..v}, flags)
        smix1(bp, r, np, flags, vp, xy, ctx_i);

        // 28: SMix2_r(B_i, p2floor(n), Nloop_rw, V_{u..v}, flags)
        smix2(bp, r, prev_power_of_two(np), nloop_rw, flags, vp, xy, ctx_i);
        vchunk += nchunk;
    }

    // 30: for i = 0 to p - 1 do
    for i in 0..p as usize {
        let bp_0 = b.add(i.wrapping_mul(s));

        // 31: SMix2_r(B_i, N, Nloop_all - Nloop_rw, V, flags excluding YESCRYPT_RW)
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

/// Compute first loop of `B = SMix_r(B, N)`.
///
/// The input B must be 128r bytes in length; the temporary storage V must be 128rN bytes in length;
/// the temporary storage XY must be 256r bytes in length.
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

    // 1: X <-- B
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

    // 2: for i = 0 to N - 1 do
    for i in 0..n {
        // 3: V_i <-- X
        blkcpy(v.add(usize::try_from(i).unwrap().wrapping_mul(s)), x, s);
        if flags.contains(Flags::RW) && i > 1 {
            let j = wrap(integerify(x, r), i);
            blkxor(x, v.add(usize::try_from(j).unwrap().wrapping_mul(s)), s);
        }

        // 4: X <-- H(X)
        if !ctx.is_null() {
            blockmix_pwxform(x, ctx, r);
        } else {
            salsa20::blockmix_salsa8(x, y, r);
        }
    }

    /* B' <-- X */
    for k in 0..2usize.wrapping_mul(r) {
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

/// Compute second loop of `B = SMix_r(B, N)`.
///
/// The input B must be 128r bytes in length; the temporary storage V must be 128rN bytes in length;
/// the temporary storage XY must be 256r bytes in length.  The value N must be a power of 2
/// greater than 1.
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
    let s = 32usize.wrapping_mul(r);
    let x = xy;
    let y = xy.add(s);

    /* X <-- B */
    for k in 0..2usize.wrapping_mul(r) {
        for i in 0..16usize {
            *x.add(k.wrapping_mul(16usize).wrapping_add(i)) = le32dec(
                b.add(
                    k.wrapping_mul(16usize)
                        .wrapping_add(i.wrapping_mul(5usize).wrapping_rem(16usize)),
                ),
            );
        }
    }

    // 6: for i = 0 to N - 1 do
    for _ in 0..nloop {
        // 7: j <-- Integerify(X) mod N
        let j = integerify(x, r) & n.wrapping_sub(1);

        // 8.1: X <-- X xor V_j
        blkxor(x, v.add(usize::try_from(j).unwrap().wrapping_mul(s)), s);

        // V_j <-- X
        if flags.contains(Flags::RW) {
            blkcpy(v.add(usize::try_from(j).unwrap().wrapping_mul(s)), x, s);
        }

        // 8.2: X <-- H(X)
        if !ctx.is_null() {
            blockmix_pwxform(x, ctx, r);
        } else {
            salsa20::blockmix_salsa8(x, y, r);
        }
    }

    // 10: B' <-- X
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

/// Compute B = BlockMix_pwxform{salsa20/2, ctx, r}(B).
///
/// The input B must be 128r bytes in length.
unsafe fn blockmix_pwxform(b: *mut u32, ctx: *mut PwxformCtx, r: usize) {
    let mut x = [0u32; 16];

    // Convert 128-byte blocks to PWXbytes blocks
    // 1: r_1 <-- 128r / PWXbytes
    let r1 = 128usize.wrapping_mul(r).wrapping_div(4 * 2 * 8);

    // 2: X <-- B'_{r_1 - 1}
    blkcpy(
        x.as_mut_ptr(),
        b.add(
            r1.wrapping_sub(1usize)
                .wrapping_mul((4usize * 2 * 8).wrapping_div(size_of::<u32>())),
        ),
        (4usize * 2 * 8).wrapping_div(size_of::<u32>()),
    );

    // 3: for i = 0 to r_1 - 1 do
    for i in 0..r1 {
        // 4: if r_1 > 1
        if r1 > 1 {
            // 5: X <-- X xor B'_i
            blkxor(
                x.as_mut_ptr(),
                b.add(i.wrapping_mul((4usize * 2 * 8).wrapping_div(size_of::<u32>()))),
                (4usize * 2 * 8).wrapping_div(size_of::<u32>()),
            );
        }

        // 7: X <-- pwxform(X)
        pwxform(x.as_mut_ptr(), ctx);

        // 8: B'_i <-- X
        blkcpy(
            b.add(i.wrapping_mul((4usize * 2 * 8).wrapping_div(size_of::<u32>()))),
            x.as_mut_ptr(),
            (4usize * 2 * 8).wrapping_div(size_of::<u32>()),
        );
    }

    // 10: i <-- floor((r_1 - 1) * PWXbytes / 64)
    let i = r1.wrapping_sub(1).wrapping_mul(4 * 2 * 8).wrapping_div(64);

    // 11: B_i <-- H(B_i)
    salsa20::salsa20_2(b.add(i.wrapping_mul(16)));

    // 12: for i = i + 1 to 2r - 1 do
    for i in (i + 1)..(2 * r) {
        blkxor(
            b.add(i.wrapping_mul(16usize)),
            b.add(i.wrapping_sub(1usize).wrapping_mul(16usize)),
            16_usize,
        );
        salsa20::salsa20_2(b.add(i.wrapping_mul(16)));
    }
}

/// Transform the provided block using the provided S-boxes.
unsafe fn pwxform(b: *mut u32, ctx: *mut PwxformCtx) {
    let x0 = b as *mut [[u32; 2]; 2];
    let s0 = (*ctx).s0;
    let s1 = (*ctx).s1;
    let s2 = (*ctx).s2;
    let mut w = (*ctx).w;

    // 1: for i = 0 to PWXrounds - 1 do
    for i in 0..6 {
        // 2: for j = 0 to PWXgather - 1 do
        for j in 0..4 {
            let mut xl: u32 = (*x0.add(j))[0][0];
            let mut xh: u32 = (*x0.add(j))[0][1];

            // 3: p0 <-- (lo(B_{j,0}) & Smask) / (PWXsimple * 8)
            let p0 = s0.add((xl as usize & (((1 << 8) - 1) * 2 * 8)) / 8);

            // 4: p1 <-- (hi(B_{j,0}) & Smask) / (PWXsimple * 8)
            let p1 = s1.add((xh as usize & (((1 << 8) - 1) * 2 * 8)) / 8);

            // 5: for k = 0 to PWXsimple - 1 do
            for k in 0..2 {
                // 6: B_{j,k} <-- (hi(B_{j,k}) * lo(B_{j,k}) + S0_{p0,k}) xor S1_{p1,k}
                let s0 = (((*p0.add(k))[1] as u64) << 32).wrapping_add((*p0.add(k))[0] as u64);
                let s1 = (((*p1.add(k))[1] as u64) << 32).wrapping_add((*p1.add(k))[0] as u64);

                xl = (*x0.add(j))[k][0];
                xh = (*x0.add(j))[k][1];

                let mut x = (xh as u64).wrapping_mul(xl as u64);
                x = x.wrapping_add(s0);
                x ^= s1;

                (*x0.add(j))[k][0] = x as u32;
                (*x0.add(j))[k][1] = (x >> 32) as u32;

                // 8: if (i != 0) and (i != PWXrounds - 1)
                if i != 0 && i != (6 - 1) {
                    // 9: S2_w <-- B_j
                    (*s2.add(w))[0] = x as u32;
                    (*s2.add(w))[1] = (x >> 32) as u32;
                    w += 1;
                }
            }
        }
    }

    // 14: (S0, S1, S2) <-- (S2, S0, S1)
    (*ctx).s0 = s2;
    (*ctx).s1 = s0;
    (*ctx).s2 = s1;

    // 15: w <-- w mod 2^Swidth
    (*ctx).w = w & (((1usize) << 8usize) * 2usize - 1usize);
}
