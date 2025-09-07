//! pwxform: parallel wide transformation

use core::mem::transmute;

use crate::{salsa20, xor};

// These are tunable, but they must meet certain constraints.
const PWXSIMPLE: usize = 2;
const PWXGATHER: usize = 4;
const PWXROUNDS: usize = 6;
const SWIDTH: usize = 8;

// Derived values.  Not tunable on their own.
const PWXBYTES: usize = PWXGATHER * PWXSIMPLE * 8;
const PWXWORDS: usize = PWXBYTES / size_of::<u32>();
const SMASK: usize = ((1 << SWIDTH) - 1) * PWXSIMPLE * 8;
pub(crate) const SBYTES: usize = 3 * (1 << SWIDTH) * PWXSIMPLE * 8;
pub(crate) const SWORDS: usize = SBYTES / size_of::<u32>();
pub(crate) const RMIN: usize = PWXBYTES.div_ceil(128);

/// Parallel wide transformation (pwxform) context.
pub(crate) struct PwxformCtx<'a> {
    pub(crate) s0: &'a mut [[u32; 2]],
    pub(crate) s1: &'a mut [[u32; 2]],
    pub(crate) s2: &'a mut [[u32; 2]],
    pub(crate) w: usize,
}

impl<'a> PwxformCtx<'a> {
    /// Compute `B = BlockMix_pwxform{salsa20/2, ctx, r}(B)`.
    ///
    /// The input `B` must be 128r bytes in length.
    pub(crate) fn blockmix_pwxform(&mut self, b: &mut [u32], r: usize) {
        // Convert 128-byte blocks to PWXbytes blocks
        let (b, _b) = b.as_chunks_mut::<PWXWORDS>();
        assert_eq!(b.len(), 2 * r);
        assert!(_b.is_empty());

        // 1: r_1 <-- 128r / PWXbytes
        let r1 = (128 * r) / PWXBYTES;

        // 2: X <-- B'_{r_1 - 1}
        let mut x = b[r1 - 1];

        // 3: for i = 0 to r_1 - 1 do
        #[allow(clippy::needless_range_loop)]
        for i in 0..r1 {
            // 4: if r_1 > 1
            if r1 > 1 {
                // 5: X <-- X xor B'_i
                xor(&mut x, &b[i]);
            }

            // 7: X <-- pwxform(X)
            self.pwxform(&mut x);

            // 8: B'_i <-- X
            b[i] = x;
        }

        // 10: i <-- floor((r_1 - 1) * PWXbytes / 64)
        let i = (r1 - 1) * PWXBYTES / 64;

        // 11: B_i <-- H(B_i)
        salsa20::salsa20_2(&mut b[i]);

        // 12: for i = i + 1 to 2r - 1 do
        for i in (i + 1)..(2 * r) {
            let [bim1, bi] = b.get_disjoint_mut([i - 1, i]).unwrap();

            /* 13: B_i <-- H(B_i xor B_{i-1}) */
            xor(bi, bim1);
            salsa20::salsa20_2(bi);
        }
    }

    /// Transform the provided block using the provided S-boxes.
    fn pwxform(&mut self, b: &mut [u32; 16]) {
        let xptr = reshape_block(b);
        let mut w = self.w;

        // 1: for i = 0 to PWXrounds - 1 do
        for i in 0..PWXROUNDS {
            // 2: for j = 0 to PWXgather - 1 do
            #[allow(clippy::needless_range_loop)]
            for j in 0..PWXGATHER {
                let mut xl: u32 = xptr[j][0][0];
                let mut xh: u32 = xptr[j][0][1];

                // 3: p0 <-- (lo(B_{j,0}) & Smask) / (PWXsimple * 8)
                let p0 = &self.s0[(xl as usize & SMASK) / 8..];

                // 4: p1 <-- (hi(B_{j,0}) & Smask) / (PWXsimple * 8)
                let p1 = &self.s1[(xh as usize & SMASK) / 8..];

                // 5: for k = 0 to PWXsimple - 1 do
                for k in 0..PWXSIMPLE {
                    // 6: B_{j,k} <-- (hi(B_{j,k}) * lo(B_{j,k}) + S0_{p0,k}) xor S1_{p1,k}
                    let s0 = ((p0[k][1] as u64) << 32).wrapping_add(p0[k][0] as u64);
                    let s1 = ((p1[k][1] as u64) << 32).wrapping_add(p1[k][0] as u64);

                    xl = xptr[j][k][0];
                    xh = xptr[j][k][1];

                    let mut x = (xh as u64).wrapping_mul(xl as u64);
                    x = x.wrapping_add(s0);
                    x ^= s1;

                    xptr[j][k][0] = x as u32;
                    xptr[j][k][1] = (x >> 32) as u32;

                    // 8: if (i != 0) and (i != PWXrounds - 1)
                    if i != 0 && i != (PWXROUNDS - 1) {
                        // 9: S2_w <-- B_j
                        self.s2[w][0] = x as u32;
                        self.s2[w][1] = (x >> 32) as u32;
                        w += 1;
                    }
                }
            }
        }

        // 14: (S0, S1, S2) <-- (S2, S0, S1)
        core::mem::swap(&mut self.s0, &mut self.s2);
        core::mem::swap(&mut self.s1, &mut self.s2);

        // 15: w <-- w mod 2^Swidth
        self.w = w & ((1 << SWIDTH) * PWXSIMPLE - 1);
    }
}

fn reshape_block(b: &mut [u32; 16]) -> &mut [[[u32; PWXSIMPLE]; 2]; 4] {
    unsafe { transmute(b) }
}
