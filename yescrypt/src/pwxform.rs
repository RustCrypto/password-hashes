//! pwxform stands for "parallel wide transformation", although it can as well be tuned to be as
//! narrow as one 64-bit lane.
//!
//! It operates on 64-bit lanes which are designed to be grouped into wider "simple SIMD" lanes,
//! which are in turn possibly grouped into an even wider "gather SIMD" vector.

use crate::{
    salsa20,
    util::{slice_as_chunks_mut, xor},
};

/// Number of 64-bit lanes per "simple SIMD" lane (requiring only arithmetic and bitwise operations
/// on its 64-bit elements). Must be a power of 2.
const PWXSIMPLE: usize = 2;

/// Number of parallel "simple SIMD" lanes per "gather SIMD" vector (requiring "S-box lookups" of
/// values as wide as a "simple SIMD" lane from PWXgather typically non-contiguous memory
/// locations). Must be a power of 2.
const PWXGATHER: usize = 4;

/// Number of sequential rounds of pwxform’s basic transformation. Must be a power of 2, plus 2
/// (e.g. 3, 4, 6, 10).
const PWXROUNDS: usize = 6;

/// Number of S-box index bits, thereby controlling the size of each of pwxform’s two S-boxes
/// (in "simple SIMD" wide elements).
const SWIDTH: usize = 8;

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

impl PwxformCtx<'_> {
    /// Compute `B = BlockMix_pwxform{salsa20/2, ctx, r}(B)`. Input `B` must be 128 bytes in length.
    ///
    /// `BlockMix_pwxform` differs from scrypt’s `BlockMix` in that it doesn’t shuffle output
    /// sub-blocks, uses pwxform in place of Salsa20/8 for as long as sub-blocks processed with
    /// pwxform fit in the provided block B, and finally uses Salsa20/2 (that is, Salsa20 with only
    /// one double-round) to post-process the last sub-block output by pwxform (thereby finally
    /// mixing pwxform’s parallel lanes).
    pub(crate) fn blockmix_pwxform(&mut self, b: &mut [u32], r: usize) {
        // Convert 128-byte blocks to PWXbytes blocks
        // TODO(tarcieri): use upstream `[T]::as_chunks_mut` when MSRV is 1.88
        let (b, _b) = slice_as_chunks_mut::<_, PWXWORDS>(b);
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
            // TODO(tarcieri): use `get_disjoint_mut` when MSRV is 1.86
            let (bim1, bi) = b[(i - 1)..i].split_at_mut(1);
            let (bim1, bi) = (&bim1[0], &mut bi[0]);

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
                    let s0 = (u64::from(p0[k][1]) << 32).wrapping_add(u64::from(p0[k][0]));
                    let s1 = (u64::from(p1[k][1]) << 32).wrapping_add(u64::from(p1[k][0]));

                    xl = xptr[j][k][0];
                    xh = xptr[j][k][1];

                    let mut x = u64::from(xh).wrapping_mul(u64::from(xl));
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

#[allow(unsafe_code)]
pub(crate) fn reshape_block(b: &mut [u32; 16]) -> &mut [[[u32; PWXSIMPLE]; 2]; 4] {
    const {
        assert!(
            size_of::<[u32; 16]>() == size_of::<[[[u32; PWXSIMPLE]; 2]; 4]>(),
            "PWXSIMPLE is incorrectly sized"
        );
    }

    unsafe { &mut *core::ptr::from_mut(b).cast() }
}
