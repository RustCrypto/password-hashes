//! Argon2 memory block functions

use core::{
    convert::{AsMut, AsRef},
    num::Wrapping,
    ops::{BitXor, BitXorAssign},
};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

const TRUNC: u64 = u32::MAX as u64;

#[rustfmt::skip]
macro_rules! permute_step {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {
        $a = (Wrapping($a) + Wrapping($b) + (Wrapping(2) * Wrapping(($a & TRUNC) * ($b & TRUNC)))).0;
        $d = ($d ^ $a).rotate_right(32);
        $c = (Wrapping($c) + Wrapping($d) + (Wrapping(2) * Wrapping(($c & TRUNC) * ($d & TRUNC)))).0;
        $b = ($b ^ $c).rotate_right(24);

        $a = (Wrapping($a) + Wrapping($b) + (Wrapping(2) * Wrapping(($a & TRUNC) * ($b & TRUNC)))).0;
        $d = ($d ^ $a).rotate_right(16);
        $c = (Wrapping($c) + Wrapping($d) + (Wrapping(2) * Wrapping(($c & TRUNC) * ($d & TRUNC)))).0;
        $b = ($b ^ $c).rotate_right(63);
    };
}

macro_rules! permute {
    (
        $v0:expr, $v1:expr, $v2:expr, $v3:expr,
        $v4:expr, $v5:expr, $v6:expr, $v7:expr,
        $v8:expr, $v9:expr, $v10:expr, $v11:expr,
        $v12:expr, $v13:expr, $v14:expr, $v15:expr,
    ) => {
        permute_step!($v0, $v4, $v8, $v12);
        permute_step!($v1, $v5, $v9, $v13);
        permute_step!($v2, $v6, $v10, $v14);
        permute_step!($v3, $v7, $v11, $v15);
        permute_step!($v0, $v5, $v10, $v15);
        permute_step!($v1, $v6, $v11, $v12);
        permute_step!($v2, $v7, $v8, $v13);
        permute_step!($v3, $v4, $v9, $v14);
    };
}

#[cfg(any(target_arch = "x86_64"))]
cpufeatures::new!(avx2_cpuid, "avx2");

/// Structure for the (1 KiB) memory block implemented as 128 64-bit words.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
#[repr(align(64))]
pub struct Block([u64; Self::SIZE / 8]);

impl Block {
    /// Memory block size in bytes
    pub const SIZE: usize = 1024;

    /// Returns a Block initialized with zeros.
    pub const fn new() -> Self {
        Self([0u64; Self::SIZE / 8])
    }

    pub(crate) fn as_bytes(&self) -> &[u8; Self::SIZE] {
        unsafe { &*(self.0.as_ptr() as *const [u8; Self::SIZE]) }
    }

    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8; Self::SIZE] {
        unsafe { &mut *(self.0.as_mut_ptr() as *mut [u8; Self::SIZE]) }
    }

    pub(crate) fn compress(rhs: &Self, lhs: &Self) -> Self {
        #[cfg(any(target_arch = "x86_64"))]
        {
            let (_, avx2) = avx2_cpuid::init_get();
            if avx2 {
                return unsafe { Self::compress_avx2(rhs, lhs) };
            }
        }
        Self::compress_soft(rhs, lhs)
    }

    fn compress_soft(rhs: &Self, lhs: &Self) -> Self {
        let r = *rhs ^ lhs;

        // Apply permutations rowwise
        let mut q = r;
        for chunk in q.0.chunks_exact_mut(16) {
            #[rustfmt::skip]
            permute!(
                chunk[0], chunk[1], chunk[2], chunk[3],
                chunk[4], chunk[5], chunk[6], chunk[7],
                chunk[8], chunk[9], chunk[10], chunk[11],
                chunk[12], chunk[13], chunk[14], chunk[15],
            );
        }

        // Apply permutations columnwise
        for i in 0..8 {
            let b = i * 2;

            #[rustfmt::skip]
            permute!(
                q.0[b], q.0[b + 1],
                q.0[b + 16], q.0[b + 17],
                q.0[b + 32], q.0[b + 33],
                q.0[b + 48], q.0[b + 49],
                q.0[b + 64], q.0[b + 65],
                q.0[b + 80], q.0[b + 81],
                q.0[b + 96], q.0[b + 97],
                q.0[b + 112], q.0[b + 113],
            );
        }

        q ^= &r;
        q
    }

    #[cfg(any(target_arch = "x86_64"))]
    #[target_feature(enable = "avx2")]
    unsafe fn compress_avx2(rhs: &Self, lhs: &Self) -> Self {
        let r = *rhs ^ lhs;

        // Apply permutations rowwise
        let mut q = r;
        for chunk in q.0.chunks_exact_mut(16) {
            #[rustfmt::skip]
            permute!(
                chunk[0], chunk[1], chunk[2], chunk[3],
                chunk[4], chunk[5], chunk[6], chunk[7],
                chunk[8], chunk[9], chunk[10], chunk[11],
                chunk[12], chunk[13], chunk[14], chunk[15],
            );
        }

        // Apply permutations columnwise
        for i in 0..8 {
            let b = i * 2;

            #[rustfmt::skip]
            permute!(
                q.0[b], q.0[b + 1],
                q.0[b + 16], q.0[b + 17],
                q.0[b + 32], q.0[b + 33],
                q.0[b + 48], q.0[b + 49],
                q.0[b + 64], q.0[b + 65],
                q.0[b + 80], q.0[b + 81],
                q.0[b + 96], q.0[b + 97],
                q.0[b + 112], q.0[b + 113],
            );
        }

        q ^= &r;
        q
    }
}

impl Default for Block {
    fn default() -> Self {
        Self([0u64; Self::SIZE / 8])
    }
}

impl AsRef<[u64]> for Block {
    fn as_ref(&self) -> &[u64] {
        &self.0
    }
}

impl AsMut<[u64]> for Block {
    fn as_mut(&mut self) -> &mut [u64] {
        &mut self.0
    }
}

impl BitXor<&Block> for Block {
    type Output = Block;

    fn bitxor(mut self, rhs: &Block) -> Self::Output {
        self ^= rhs;
        self
    }
}

impl BitXorAssign<&Block> for Block {
    fn bitxor_assign(&mut self, rhs: &Block) {
        for (dst, src) in self.0.iter_mut().zip(rhs.0.iter()) {
            *dst ^= src;
        }
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Block {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn compress_avx2() {
        let lhs = Block([
            0, 0, 0, 2048, 4, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let rhs = Block([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        let result = Block::compress_soft(&rhs, &lhs);
        let result_av2 = unsafe { Block::compress_avx2(&rhs, &lhs) };

        assert_eq!(result, result_av2);
    }
}
