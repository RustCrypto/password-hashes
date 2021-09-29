//! Argon2 memory block functions

use core::{
    convert::{AsMut, AsRef, TryInto},
    num::Wrapping,
    ops::{BitXor, BitXorAssign},
};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Structure for the (1 KiB) memory block implemented as 128 64-bit words.
#[derive(Copy, Clone, Debug)]
pub struct Block([u64; Self::SIZE / 8]);

impl Block {
    /// Memory block size in bytes
    pub const SIZE: usize = 1024;

    pub(crate) fn compress(a: &Self, b: &Self) -> Self {
        let r = *a ^ b;

        // Apply permutations rowwise
        let mut q = r;
        for chunk in q.0.chunks_exact_mut(16) {
            permutate(
                &mut chunk[0..2].try_into().unwrap(),
                &mut chunk[2..4].try_into().unwrap(),
                &mut chunk[4..6].try_into().unwrap(),
                &mut chunk[6..8].try_into().unwrap(),
                &mut chunk[8..10].try_into().unwrap(),
                &mut chunk[10..12].try_into().unwrap(),
                &mut chunk[12..14].try_into().unwrap(),
                &mut chunk[14..16].try_into().unwrap(),
            );
        }

        // Apply permutations columnwise
        let mut z = q;
        for chunk in z.0.chunks_exact_mut(128) {
            permutate(
                &mut chunk[0..2].try_into().unwrap(),
                &mut chunk[16..18].try_into().unwrap(),
                &mut chunk[32..34].try_into().unwrap(),
                &mut chunk[48..50].try_into().unwrap(),
                &mut chunk[64..66].try_into().unwrap(),
                &mut chunk[80..82].try_into().unwrap(),
                &mut chunk[96..98].try_into().unwrap(),
                &mut chunk[112..114].try_into().unwrap(),
            );
        }

        z ^= &r;
        z
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
        for (dst, src) in self.0.iter_mut().zip(rhs.0.iter().copied()) {
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

fn permutate(
    r0: &mut [u64; 2],
    r1: &mut [u64; 2],
    r2: &mut [u64; 2],
    r3: &mut [u64; 2],
    r4: &mut [u64; 2],
    r5: &mut [u64; 2],
    r6: &mut [u64; 2],
    r7: &mut [u64; 2],
) {
    fn step(a: &mut u64, b: &mut u64, c: &mut u64, d: &mut u64) {
        const TRUNC: u64 = u32::MAX as u64;

        *a = (Wrapping(*a)
            + Wrapping(*b)
            + (Wrapping(2) * Wrapping(*a & TRUNC) * Wrapping(*b & TRUNC)))
        .0;
        *d = (*d ^ *a).rotate_right(32);
        *c = (Wrapping(*c)
            + Wrapping(*d)
            + (Wrapping(2) * Wrapping(*c & TRUNC) * Wrapping(*d & TRUNC)))
        .0;
        *b = (*b ^ *c).rotate_right(24);

        *a = (Wrapping(*a)
            + Wrapping(*b)
            + (Wrapping(2) * Wrapping(*a & TRUNC) * Wrapping(*b & TRUNC)))
        .0;
        *d = (*d ^ *a).rotate_right(16);
        *c = (Wrapping(*c)
            + Wrapping(*d)
            + (Wrapping(2) * Wrapping(*c & TRUNC) * Wrapping(*d & TRUNC)))
        .0;
        *b = (*b ^ *c).rotate_right(63);
    }

    step(&mut r0[0], &mut r2[0], &mut r4[0], &mut r6[0]);
    step(&mut r0[1], &mut r2[1], &mut r4[1], &mut r6[1]);

    step(&mut r1[0], &mut r3[0], &mut r5[0], &mut r7[0]);
    step(&mut r1[1], &mut r3[1], &mut r5[1], &mut r7[1]);

    step(&mut r0[0], &mut r2[1], &mut r5[0], &mut r7[1]);
    step(&mut r0[1], &mut r3[0], &mut r5[1], &mut r6[0]);

    step(&mut r1[0], &mut r3[1], &mut r4[0], &mut r6[1]);
    step(&mut r1[1], &mut r2[0], &mut r4[1], &mut r7[0]);
}
