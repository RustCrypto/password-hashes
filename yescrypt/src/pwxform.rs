//! pwxform: parallel wide transformation

use crate::{
    common::{blkcpy, blkxor},
    salsa20,
};
use alloc::vec::Vec;
use core::{marker::PhantomData, ptr};

// These are tunable, but they must meet certain constraints.
const PWXSIMPLE: usize = 2;
const PWXGATHER: usize = 4;
const PWXROUNDS: usize = 6;
const SWIDTH: usize = 8;

// Derived values.  Not tunable on their own.
const PWXBYTES: usize = PWXGATHER * PWXSIMPLE * 8;
const PWXWORDS: usize = PWXBYTES / size_of::<u32>();
const SMASK: usize = ((1 << SWIDTH) - 1) * PWXSIMPLE * 8;
const SBYTES: usize = 3 * (1 << SWIDTH) * PWXSIMPLE * 8;
pub(crate) const SWORDS: usize = SBYTES / size_of::<u32>();
pub(crate) const RMIN: usize = PWXBYTES.div_ceil(128);

/// Parallel wide transformation (pwxform) context.
// TODO(tarcieri): have `PwxformCtx` own its state instead of using pointers
#[derive(Copy, Clone)]
pub(crate) struct PwxformCtx<'a> {
    pub(crate) s: *mut u32,
    pub(crate) s0: *mut [u32; 2],
    pub(crate) s1: *mut [u32; 2],
    pub(crate) s2: *mut [u32; 2],
    pub(crate) w: usize,
    phantom: PhantomData<&'a ()>,
}

impl<'a> PwxformCtx<'a> {
    /// Initialize a vector of parallel wide transformation contexts, one for each degree of
    /// parallelism (i.e. the `p` parameter).
    pub(crate) fn new(p: usize, s: &'a mut [u32]) -> Vec<PwxformCtx<'a>> {
        assert_eq!(s.len(), SWORDS * p, "state buffer is incorrectly sized");
        let mut pwxform_ctx = Vec::with_capacity(p);

        for i in 0..p {
            let mut ctx = PwxformCtx {
                s: ptr::null_mut(),
                s0: ptr::null_mut(),
                s1: ptr::null_mut(),
                s2: ptr::null_mut(),
                w: 0,
                phantom: PhantomData,
            };

            let offset = i * SWORDS;
            ctx.s = s[offset..(offset + SWORDS)].as_mut_ptr();
            pwxform_ctx.push(ctx)
        }

        pwxform_ctx
    }

    /// Compute `B = BlockMix_pwxform{salsa20/2, ctx, r}(B)`.
    ///
    /// The input `B` must be 128r bytes in length.
    pub(crate) unsafe fn blockmix_pwxform(&mut self, b: *mut u32, r: usize) {
        let mut x = [0u32; 16];

        // Convert 128-byte blocks to PWXbytes blocks
        // 1: r_1 <-- 128r / PWXbytes
        let r1 = (128 * r) / PWXBYTES;

        // 2: X <-- B'_{r_1 - 1}
        blkcpy(x.as_mut_ptr(), b.add((r1 - 1) * PWXWORDS), PWXWORDS);

        // 3: for i = 0 to r_1 - 1 do
        for i in 0..r1 {
            // 4: if r_1 > 1
            if r1 > 1 {
                // 5: X <-- X xor B'_i
                blkxor(x.as_mut_ptr(), b.add(i * PWXWORDS), PWXWORDS);
            }

            // 7: X <-- pwxform(X)
            self.pwxform(&mut x);

            // 8: B'_i <-- X
            blkcpy(b.add(i * PWXWORDS), x.as_mut_ptr(), PWXWORDS);
        }

        // 10: i <-- floor((r_1 - 1) * PWXbytes / 64)
        let i = (r1 - 1) * PWXBYTES / 64;

        // 11: B_i <-- H(B_i)
        salsa20::salsa20_2(b.add(i * 16));

        // 12: for i = i + 1 to 2r - 1 do
        for i in (i + 1)..(2 * r) {
            blkxor(b.add(i * 16), b.add((i - 1) * 16), 16);
            salsa20::salsa20_2(b.add(i * 16));
        }
    }

    /// Transform the provided block using the provided S-boxes.
    unsafe fn pwxform(&mut self, b: &mut [u32; 16]) {
        let xptr: *mut [[u32; PWXSIMPLE]; 2] = b.as_mut_ptr().cast();
        let s0 = self.s0;
        let s1 = self.s1;
        let s2 = self.s2;
        let mut w = self.w;

        // 1: for i = 0 to PWXrounds - 1 do
        for i in 0..PWXROUNDS {
            // 2: for j = 0 to PWXgather - 1 do
            for j in 0..PWXGATHER {
                let mut xl: u32 = (*xptr.add(j))[0][0];
                let mut xh: u32 = (*xptr.add(j))[0][1];

                // 3: p0 <-- (lo(B_{j,0}) & Smask) / (PWXsimple * 8)
                let p0 = s0.add((xl as usize & SMASK) / 8);

                // 4: p1 <-- (hi(B_{j,0}) & Smask) / (PWXsimple * 8)
                let p1 = s1.add((xh as usize & SMASK) / 8);

                // 5: for k = 0 to PWXsimple - 1 do
                for k in 0..PWXSIMPLE {
                    // 6: B_{j,k} <-- (hi(B_{j,k}) * lo(B_{j,k}) + S0_{p0,k}) xor S1_{p1,k}
                    let s0 = (((*p0.add(k))[1] as u64) << 32).wrapping_add((*p0.add(k))[0] as u64);
                    let s1 = (((*p1.add(k))[1] as u64) << 32).wrapping_add((*p1.add(k))[0] as u64);

                    xl = (*xptr.add(j))[k][0];
                    xh = (*xptr.add(j))[k][1];

                    let mut x = (xh as u64).wrapping_mul(xl as u64);
                    x = x.wrapping_add(s0);
                    x ^= s1;

                    (*xptr.add(j))[k][0] = x as u32;
                    (*xptr.add(j))[k][1] = (x >> 32) as u32;

                    // 8: if (i != 0) and (i != PWXrounds - 1)
                    if i != 0 && i != (PWXROUNDS - 1) {
                        // 9: S2_w <-- B_j
                        (*s2.add(w))[0] = x as u32;
                        (*s2.add(w))[1] = (x >> 32) as u32;
                        w += 1;
                    }
                }
            }
        }

        // 14: (S0, S1, S2) <-- (S2, S0, S1)
        self.s0 = s2;
        self.s1 = s0;
        self.s2 = s1;

        // 15: w <-- w mod 2^Swidth
        self.w = w & ((1 << SWIDTH) * PWXSIMPLE - 1);
    }
}
