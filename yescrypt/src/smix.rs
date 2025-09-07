//! Core sequential memory-hard mixing function, inherited from the scrypt key derivation function.

#![allow(clippy::too_many_arguments)]

use alloc::vec::Vec;

use crate::{
    Flags,
    pwxform::{PwxformCtx, SWORDS},
    salsa20,
    util::{cast_slice, hmac_sha256, slice_as_chunks_mut, xor},
};

const SBYTES: u64 = crate::pwxform::SBYTES as u64;

/// Compute `B = SMix_r(B, N)`.
///
/// The input B must be 128rp bytes in length; the temporary storage V must be 128rN bytes in
/// length; the temporary storage XY must be 256r bytes in length.  The value N must be a power of 2
/// greater than 1.
pub(crate) fn smix(
    b: &mut [u32],
    r: usize,
    n: u64,
    p: u32,
    t: u32,
    flags: Flags,
    v: &mut [u32],
    xy: &mut [u32],
    passwd: &mut [u8],
) {
    let s = 32 * r;

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

    // S_n = [S_i for i in 0..p]
    let mut sn = if flags.contains(Flags::RW) {
        alloc::vec![[0u32; SWORDS]; p as usize]
    } else {
        Vec::new()
    };
    let mut ctxs = Vec::with_capacity(sn.len());
    let mut sn = sn.iter_mut();

    // 11: for i = 0 to p - 1 do
    // 12: u <-- in
    #[allow(clippy::needless_range_loop)]
    for i in 0..p as usize {
        // 13: if i = p - 1
        // 14:   n <-- N - u
        // 15: end if
        // 16: v <-- u + n - 1
        let np = if i < p as usize - 1 {
            nchunk
        } else {
            n - vchunk
        };

        let bs = &mut b[(i * s)..];
        let vp = &mut v[vchunk as usize * s..];

        // 17: if YESCRYPT_RW flag is set
        let mut ctx_i = if flags.contains(Flags::RW) {
            let si = sn.next().unwrap();

            // 18: SMix1_1(B_i, Sbytes / 128, S_i, no flags)
            smix1(
                bs,
                1,
                SBYTES / 128,
                Flags::empty(),
                &mut si[..],
                xy,
                &mut None,
            );

            let (s2, s10) = si.split_at_mut((1 << 8) * 4);
            let (s1, s0) = s10.split_at_mut((1 << 8) * 4);

            // 19: S2_i <-- S_{i,0...2^Swidth-1}
            // TODO(tarcieri): use upstream `[T]::as_chunks_mut` when MSRV is 1.88
            let (s2, _) = slice_as_chunks_mut::<_, 2>(s2);

            // 20: S1_i <-- S_{i,2^Swidth...2*2^Swidth-1}
            // TODO(tarcieri): use upstream `[T]::as_chunks_mut` when MSRV is 1.88
            let (s1, _) = slice_as_chunks_mut::<_, 2>(s1);

            // 21: S0_i <-- S_{i,2*2^Swidth...3*2^Swidth-1}
            // TODO(tarcieri): use upstream `[T]::as_chunks_mut` when MSRV is 1.88
            let (s0, _) = slice_as_chunks_mut::<_, 2>(s0);

            // 22: w_i <-- 0
            let w = 0;

            // 23: if i = 0
            if i == 0 {
                // 24: passwd <-- HMAC-SHA256(B_{0,2r-1}, passwd)
                let digest = hmac_sha256(cast_slice(&bs[(s - 16)..s]), &passwd[..32]);
                passwd[..32].copy_from_slice(&digest);
            }

            ctxs.push(PwxformCtx { s0, s1, s2, w });
            ctxs.last_mut()
        } else {
            None
        };

        // 27: SMix1_r(B_i, n, V_{u..v}, flags)
        smix1(bs, r, np, flags, vp, xy, &mut ctx_i);

        // 28: SMix2_r(B_i, p2floor(n), Nloop_rw, V_{u..v}, flags)
        smix2(
            bs,
            r,
            prev_power_of_two(np),
            nloop_rw,
            flags,
            vp,
            xy,
            &mut ctx_i,
        );

        vchunk += nchunk;
    }

    // 30: for i = 0 to p - 1 do
    #[allow(clippy::needless_range_loop)]
    for i in 0..p as usize {
        let mut ctx_i = if flags.contains(Flags::RW) {
            Some(&mut ctxs[i])
        } else {
            None
        };

        // 31: SMix2_r(B_i, N, Nloop_all - Nloop_rw, V, flags excluding YESCRYPT_RW)
        smix2(
            &mut b[(i * s)..],
            r,
            n,
            nloop_all - nloop_rw,
            flags & !Flags::RW,
            v,
            xy,
            &mut ctx_i,
        );
    }
}

/// Compute first loop of `B = SMix_r(B, N)`.
///
/// The input B must be 128r bytes in length; the temporary storage `V` must be 128rN bytes in
/// length; the temporary storage `XY` must be 256r bytes in length.
fn smix1(
    b: &mut [u32],
    r: usize,
    n: u64,
    flags: Flags,
    v: &mut [u32],
    xy: &mut [u32],
    ctx: &mut Option<&mut PwxformCtx<'_>>,
) {
    let s = 32 * r;
    let (x, y) = xy.split_at_mut(s);

    // 1: X <-- B
    for k in 0..(2 * r) {
        for i in 0..16 {
            x[k * 16 + i] = u32::from_le(b[(k * 16) + (i * 5 % 16)]);
        }
    }

    // 2: for i = 0 to N - 1 do
    for i in 0..n {
        // 3: V_i <-- X
        v[i as usize * s..][..s].copy_from_slice(x);
        if flags.contains(Flags::RW) && i > 1 {
            let n = prev_power_of_two(i);
            let j = usize::try_from((integerify(x, r) & (n - 1)) + (i - n)).unwrap();
            xor(x, &v[j * s..][..s]);
        }

        // 4: X <-- H(X)
        match ctx {
            Some(ctx) => ctx.blockmix_pwxform(x, r),
            None => salsa20::blockmix_salsa8(x, y, r),
        }
    }

    /* B' <-- X */
    for k in 0..(2 * r) {
        for i in 0..16 {
            b[(k * 16) + ((i * 5) % 16)] = (x[k * 16 + i]).to_le();
        }
    }
}

/// Compute second loop of `B = SMix_r(B, N)`.
///
/// The input B must be 128r bytes in length; the temporary storage V must be 128rN bytes in length;
/// the temporary storage XY must be 256r bytes in length.  The value N must be a power of 2
/// greater than 1.
fn smix2(
    b: &mut [u32],
    r: usize,
    n: u64,
    nloop: u64,
    flags: Flags,
    v: &mut [u32],
    xy: &mut [u32],
    ctx: &mut Option<&mut PwxformCtx<'_>>,
) {
    let s = 32 * r;
    let (x, y) = xy.split_at_mut(s);

    /* X <-- B */
    for k in 0..(2 * r) {
        for i in 0..16usize {
            x[k * 16 + i] = u32::from_le(b[(k * 16) + (i * 5 % 16)]);
        }
    }

    // 6: for i = 0 to N - 1 do
    for _ in 0..nloop {
        // 7: j <-- Integerify(X) mod N
        let j = usize::try_from(integerify(x, r) & (n - 1)).unwrap();

        // 8.1: X <-- X xor V_j
        xor(x, &v[j * s..][..s]);

        // V_j <-- X
        if flags.contains(Flags::RW) {
            v[j as usize * s..][..s].copy_from_slice(x);
        }

        // 8.2: X <-- H(X)
        match ctx {
            Some(ctx) => ctx.blockmix_pwxform(x, r),
            None => salsa20::blockmix_salsa8(x, y, r),
        }
    }

    // 10: B' <-- X
    for k in 0..(2 * r) {
        for i in 0..16 {
            b[(k * 16) + ((i * 5) % 16)] = (x[k * 16 + i]).to_le();
        }
    }
}

/// Return the result of parsing B_{2r-1} as a little-endian integer.
fn integerify(b: &[u32], r: usize) -> u64 {
    let x = &b[((2 * r) - 1) * 16..];
    ((x[13] as u64) << 32).wrapping_add(x[0] as u64)
}

/// Largest power of 2 not greater than argument.
fn prev_power_of_two(mut x: u64) -> u64 {
    let mut y;

    loop {
        y = x & (x - 1);
        if y == 0 {
            break;
        }
        x = y;
    }
    x
}
