//! pwxform: parallel wide transformation

use crate::{
    Error, Result,
    common::{blkcpy, blkxor},
    salsa20,
};
use libc::malloc;

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

impl PwxformCtx {
    /// Allocate a parallel wide transformation context.
    ///
    /// Caller is responsible for freeing it.
    // TODO(tarcieri): avoid `malloc` and `unsafe`, use RAII
    pub(crate) unsafe fn alloc(p: u32, s: *mut u32) -> Result<*mut PwxformCtx> {
        let pwxform_ctx = malloc(size_of::<PwxformCtx>() * (p as usize)) as *mut PwxformCtx;

        if pwxform_ctx.is_null() {
            return Err(Error);
        }

        for i in 0..p as usize {
            let offset = i * (((3 * (1 << 8) * 2 * 8) as usize) / size_of::<u32>());
            (*pwxform_ctx.add(i)).s = s.add(offset);
        }

        Ok(pwxform_ctx)
    }

    /// Compute `B = BlockMix_pwxform{salsa20/2, ctx, r}(B)`.
    ///
    /// The input `B` must be 128r bytes in length.
    pub(crate) unsafe fn blockmix_pwxform(&mut self, b: *mut u32, r: usize) {
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
            self.pwxform(x.as_mut_ptr());

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
    unsafe fn pwxform(&mut self, b: *mut u32) {
        let x0 = b as *mut [[u32; 2]; 2];
        let s0 = self.s0;
        let s1 = self.s1;
        let s2 = self.s2;
        let mut w = self.w;

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
        self.s0 = s2;
        self.s1 = s0;
        self.s2 = s1;

        // 15: w <-- w mod 2^Swidth
        self.w = w & (((1usize) << 8usize) * 2usize - 1usize);
    }
}
