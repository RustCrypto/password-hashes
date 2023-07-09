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

const fn _mm_shuffle2(z: i32, y: i32, x: i32, w: i32) -> i32 {
    (z << 6) | (y << 4) | (x << 2) | w
}

macro_rules! rotr32 {
    ($x:expr) => {
        _mm256_shuffle_epi32($x, _mm_shuffle2(2, 3, 0, 1))
    };
}

macro_rules! rotr24 {
    ($x:expr) => {
        _mm256_shuffle_epi8(
            $x,
            _mm256_setr_epi8(
                3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, 3, 4, 5, 6, 7, 0, 1, 2, 11,
                12, 13, 14, 15, 8, 9, 10,
            ),
        )
    };
}

macro_rules! rotr16 {
    ($x:expr) => {
        _mm256_shuffle_epi8(
            $x,
            _mm256_setr_epi8(
                2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9, 2, 3, 4, 5, 6, 7, 0, 1, 10,
                11, 12, 13, 14, 15, 8, 9,
            ),
        )
    };
}

macro_rules! rotr63 {
    ($x:expr) => {
        _mm256_xor_si256(_mm256_srli_epi64($x, 63), _mm256_add_epi64($x, $x))
    };
}

macro_rules! G1_AVX2 {
    ($A0:expr, $A1:expr, $B0:expr, $B1:expr, $C0:expr, $C1:expr, $D0:expr, $D1:expr) => {{
        let ml = _mm256_mul_epu32($A0, $B0);
        let ml = _mm256_add_epi64(ml, ml);
        $A0 = _mm256_add_epi64($A0, _mm256_add_epi64($B0, ml));
        $D0 = _mm256_xor_si256($D0, $A0);
        $D0 = rotr32!($D0);
        let ml = _mm256_mul_epu32($C0, $D0);
        let ml = _mm256_add_epi64(ml, ml);
        $C0 = _mm256_add_epi64($C0, _mm256_add_epi64($D0, ml));
        $B0 = _mm256_xor_si256($B0, $C0);
        $B0 = rotr24!($B0);
        let ml = _mm256_mul_epu32($A1, $B1);
        let ml = _mm256_add_epi64(ml, ml);
        $A1 = _mm256_add_epi64($A1, _mm256_add_epi64($B1, ml));
        $D1 = _mm256_xor_si256($D1, $A1);
        $D1 = rotr32!($D1);
        let ml = _mm256_mul_epu32($C1, $D1);
        let ml = _mm256_add_epi64(ml, ml);
        $C1 = _mm256_add_epi64($C1, _mm256_add_epi64($D1, ml));
        $B1 = _mm256_xor_si256($B1, $C1);
        $B1 = rotr24!($B1);
    }};
}

macro_rules! G2_AVX2 {
    ($A0:expr, $A1:expr, $B0:expr, $B1:expr, $C0:expr, $C1:expr, $D0:expr, $D1:expr) => {{
        let ml = _mm256_mul_epu32($A0, $B0);
        let ml = _mm256_add_epi64(ml, ml);
        $A0 = _mm256_add_epi64($A0, _mm256_add_epi64($B0, ml));
        $D0 = _mm256_xor_si256($D0, $A0);
        $D0 = rotr16!($D0);
        let ml = _mm256_mul_epu32($C0, $D0);
        let ml = _mm256_add_epi64(ml, ml);
        $C0 = _mm256_add_epi64($C0, _mm256_add_epi64($D0, ml));
        $B0 = _mm256_xor_si256($B0, $C0);
        $B0 = rotr63!($B0);
        let ml = _mm256_mul_epu32($A1, $B1);
        let ml = _mm256_add_epi64(ml, ml);
        $A1 = _mm256_add_epi64($A1, _mm256_add_epi64($B1, ml));
        $D1 = _mm256_xor_si256($D1, $A1);
        $D1 = rotr16!($D1);
        let ml = _mm256_mul_epu32($C1, $D1);
        let ml = _mm256_add_epi64(ml, ml);
        $C1 = _mm256_add_epi64($C1, _mm256_add_epi64($D1, ml));
        $B1 = _mm256_xor_si256($B1, $C1);
        $B1 = rotr63!($B1);
    }};
}

macro_rules! DIAGONALIZE_1 {
    ($A0:expr, $B0:expr, $C0:expr, $D0:expr, $A1:expr, $B1:expr, $C1:expr, $D1:expr) => {{
        $B0 = _mm256_permute4x64_epi64($B0, _mm_shuffle2(0, 3, 2, 1));
        $C0 = _mm256_permute4x64_epi64($C0, _mm_shuffle2(1, 0, 3, 2));
        $D0 = _mm256_permute4x64_epi64($D0, _mm_shuffle2(2, 1, 0, 3));
        $B1 = _mm256_permute4x64_epi64($B1, _mm_shuffle2(0, 3, 2, 1));
        $C1 = _mm256_permute4x64_epi64($C1, _mm_shuffle2(1, 0, 3, 2));
        $D1 = _mm256_permute4x64_epi64($D1, _mm_shuffle2(2, 1, 0, 3));
    }};
}

macro_rules! DIAGONALIZE_2 {
    ($A0:expr, $A1:expr, $B0:expr, $B1:expr, $C0:expr, $C1:expr, $D0:expr, $D1:expr) => {{
        let tmp1 = _mm256_blend_epi32($B0, $B1, 0xCC);
        let tmp2 = _mm256_blend_epi32($B0, $B1, 0x33);
        $B1 = _mm256_permute4x64_epi64(tmp1, _mm_shuffle2(2, 3, 0, 1));
        $B0 = _mm256_permute4x64_epi64(tmp2, _mm_shuffle2(2, 3, 0, 1));
        let tmp1 = $C0;
        $C0 = $C1;
        $C1 = tmp1;
        let tmp1 = _mm256_blend_epi32($D0, $D1, 0xCC);
        let tmp2 = _mm256_blend_epi32($D0, $D1, 0x33);
        $D0 = _mm256_permute4x64_epi64(tmp1, _mm_shuffle2(2, 3, 0, 1));
        $D1 = _mm256_permute4x64_epi64(tmp2, _mm_shuffle2(2, 3, 0, 1));
    }};
}

macro_rules! UNDIAGONALIZE_1 {
    ($A0:expr, $B0:expr, $C0:expr, $D0:expr, $A1:expr, $B1:expr, $C1:expr, $D1:expr) => {{
        $B0 = _mm256_permute4x64_epi64($B0, _mm_shuffle2(2, 1, 0, 3));
        $C0 = _mm256_permute4x64_epi64($C0, _mm_shuffle2(1, 0, 3, 2));
        $D0 = _mm256_permute4x64_epi64($D0, _mm_shuffle2(0, 3, 2, 1));
        $B1 = _mm256_permute4x64_epi64($B1, _mm_shuffle2(2, 1, 0, 3));
        $C1 = _mm256_permute4x64_epi64($C1, _mm_shuffle2(1, 0, 3, 2));
        $D1 = _mm256_permute4x64_epi64($D1, _mm_shuffle2(0, 3, 2, 1));
    }};
}

macro_rules! UNDIAGONALIZE_2 {
    ($A0:expr, $A1:expr, $B0:expr, $B1:expr, $C0:expr, $C1:expr, $D0:expr, $D1:expr) => {{
        let tmp1 = _mm256_blend_epi32($B0, $B1, 0xCC);
        let tmp2 = _mm256_blend_epi32($B0, $B1, 0x33);
        $B0 = _mm256_permute4x64_epi64(tmp1, _mm_shuffle2(2, 3, 0, 1));
        $B1 = _mm256_permute4x64_epi64(tmp2, _mm_shuffle2(2, 3, 0, 1));
        let tmp1 = $C0;
        $C0 = $C1;
        $C1 = tmp1;
        let tmp1 = _mm256_blend_epi32($D0, $D1, 0x33);
        let tmp2 = _mm256_blend_epi32($D0, $D1, 0xCC);
        $D0 = _mm256_permute4x64_epi64(tmp1, _mm_shuffle2(2, 3, 0, 1));
        $D1 = _mm256_permute4x64_epi64(tmp2, _mm_shuffle2(2, 3, 0, 1));
    }};
}

macro_rules! BLAKE2_ROUND_1 {
    ($A0:expr, $A1:expr, $B0:expr, $B1:expr, $C0:expr, $C1:expr, $D0:expr, $D1:expr) => {{
        G1_AVX2!($A0, $A1, $B0, $B1, $C0, $C1, $D0, $D1);
        G2_AVX2!($A0, $A1, $B0, $B1, $C0, $C1, $D0, $D1);
        DIAGONALIZE_1!($A0, $B0, $C0, $D0, $A1, $B1, $C1, $D1);
        G1_AVX2!($A0, $A1, $B0, $B1, $C0, $C1, $D0, $D1);
        G2_AVX2!($A0, $A1, $B0, $B1, $C0, $C1, $D0, $D1);
        UNDIAGONALIZE_1!($A0, $B0, $C0, $D0, $A1, $B1, $C1, $D1);
    }};
}

macro_rules! BLAKE2_ROUND_2 {
    ($A0:expr, $A1:expr, $B0:expr, $B1:expr, $C0:expr, $C1:expr, $D0:expr, $D1:expr) => {{
        G1_AVX2!($A0, $A1, $B0, $B1, $C0, $C1, $D0, $D1);
        G2_AVX2!($A0, $A1, $B0, $B1, $C0, $C1, $D0, $D1);
        DIAGONALIZE_2!($A0, $A1, $B0, $B1, $C0, $C1, $D0, $D1);
        G1_AVX2!($A0, $A1, $B0, $B1, $C0, $C1, $D0, $D1);
        G2_AVX2!($A0, $A1, $B0, $B1, $C0, $C1, $D0, $D1);
        UNDIAGONALIZE_2!($A0, $A1, $B0, $B1, $C0, $C1, $D0, $D1);
    }};
}

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
        Self::compress_safe(rhs, lhs)
    }

    fn compress_safe(rhs: &Self, lhs: &Self) -> Self {
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
    unsafe fn compress_avx2(rhs: &Self, lhs: &Self) -> Self {
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;

        // one u64 is 64 bits, so 4 u64s is 256 bits
        // 256 bits * 32 = 8192 bits = 1024 bytes

        // extract the data into 32 256-bit registers
        let mut state = [
            _mm256_loadu_si256(rhs.0.as_ptr().offset(0 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(1 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(2 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(3 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(4 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(5 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(6 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(7 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(8 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(9 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(10 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(11 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(12 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(13 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(14 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(15 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(16 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(17 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(18 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(19 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(20 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(21 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(22 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(23 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(24 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(25 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(26 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(27 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(28 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(29 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(30 * 4) as *const __m256i),
            _mm256_loadu_si256(rhs.0.as_ptr().offset(31 * 4) as *const __m256i),
        ];

        let block_xy = [
            _mm256_loadu_si256(lhs.0.as_ptr().offset(0 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(1 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(2 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(3 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(4 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(5 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(6 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(7 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(8 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(9 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(10 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(11 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(12 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(13 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(14 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(15 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(16 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(17 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(18 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(19 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(20 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(21 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(22 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(23 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(24 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(25 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(26 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(27 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(28 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(29 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(30 * 4) as *const __m256i),
            _mm256_loadu_si256(lhs.0.as_ptr().offset(31 * 4) as *const __m256i),
        ];

        // xor registers
        for i in 0..state.len() {
            state[i] = _mm256_xor_si256(state[i], block_xy[i]);
        }

        for i in 0..4 {
            #[rustfmt::skip]
            BLAKE2_ROUND_1!(
                state[i + 0], state[i + 4],
                state[i + 1], state[i + 5],
                state[i + 2], state[i + 6],
                state[i + 3], state[i + 7]
            );
        }

        for i in 0..4 {
            #[rustfmt::skip]
            BLAKE2_ROUND_2!(
                state[0 + i], state[1 + i],
                state[2 + i], state[3 + i],
                state[4 + i], state[5 + i],
                state[6 + i], state[7 + i]
            );
        }

        // xor registers
        for i in 0..state.len() {
            state[i] = _mm256_xor_si256(state[i], block_xy[i]);
        }

        // reapply registers
        let mut r = Self::new();
        for i in 0..state.len() {
            _mm256_storeu_si256(
                r.0.as_mut_ptr().offset(i as isize * 4) as *mut __m256i,
                state[i],
            );
        }

        r
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

        let result = Block::compress_safe(&rhs, &lhs);
        let result_av2 = unsafe { Block::compress_avx2(&rhs, &lhs) };

        assert_eq!(result, result_av2);
    }
}
