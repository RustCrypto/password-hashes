//! AVX2 block compression.
//!
//! Ported from the `__AVX2__` code paths of the Argon2 reference implementation
//! (<https://github.com/P-H-C/phc-winner-argon2>): `fill_block` in `src/opt.c`
//! and the `BlaMka` round in `src/blake2/blamka-round-opt.h`. The reference
//! implementation is available under the CC0 1.0 and Apache 2.0 licenses.
//!
//! The 1 KiB block is held as 32 `__m256i` values. Each row of 16 words is four
//! vectors. `round_1` applies the `BlaMka` round to two rows at once, `round_2`
//! to two columns (pairs of words) at once.

// Every `unsafe fn` in this module has the same safety contract: the CPU must
// support AVX2. Under that contract, every intrinsic call in this
// module is sound, so the bodies do not repeat `unsafe` blocks. The only entry
// points are the `Compressor` methods of `Avx2`, whose value proves the contract.
#![allow(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::Compressor;
use crate::Block;
use core::mem::MaybeUninit;

/// Number of 256-bit vectors in a block.
const VECS: usize = Block::SIZE / 32;

/// Block state held in AVX2 vectors.
pub(crate) type State = [__m256i; VECS];

/// AVX2 backend.
///
/// A value of this type proves that the CPU supports AVX2.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Avx2(());

impl Avx2 {
    /// Create the backend.
    ///
    /// # Safety
    /// The CPU must support AVX2.
    pub(crate) const unsafe fn new_unchecked() -> Self {
        Self(())
    }
}

impl Compressor for Avx2 {
    type State = State;

    #[inline(always)]
    fn load(self, block: &Block) -> State {
        // SAFETY: `self` proves that the CPU supports AVX2.
        unsafe { load(block) }
    }

    #[inline(always)]
    fn compress(
        self,
        state: &mut State,
        _prev: &Block,
        rhs: &Block,
        next: &mut Block,
        with_xor: bool,
    ) {
        // `state` already holds `_prev` in vectors, so it is not read again.
        // SAFETY: `self` proves that the CPU supports AVX2.
        unsafe { compress(state, rhs, next, with_xor) }
    }
}

/// Load a block into vectors.
///
/// # Safety
/// The CPU must support AVX2.
#[inline(always)]
unsafe fn load(block: &Block) -> State {
    // `block` is valid for reads of `Block::SIZE` bytes, and the loads are unaligned.
    let src = block.as_ref().as_ptr().cast::<__m256i>();
    let mut state = [_mm256_setzero_si256(); VECS];
    for (i, v) in state.iter_mut().enumerate() {
        *v = _mm256_loadu_si256(src.add(i));
    }
    state
}

/// See [`Compressor::compress`]. This is `fill_block` from the reference `opt.c`.
///
/// # Safety
/// The CPU must support AVX2.
#[inline(always)]
unsafe fn compress(state: &mut State, rhs: &Block, next: &mut Block, with_xor: bool) {
    // `rhs` and `next` are valid for reads (and `next` for writes) of `Block::SIZE`
    // bytes, and the loads and stores are unaligned.
    let rhs = rhs.as_ref().as_ptr().cast::<__m256i>();
    let next = next.as_mut().as_mut_ptr().cast::<__m256i>();

    // `block_xy` is `state ^ rhs` (and `^ next`), XORed back in after the permutation.
    // Every element is written before it is read.
    let mut block_xy = [MaybeUninit::<__m256i>::uninit(); VECS];

    if with_xor {
        for i in 0..VECS {
            state[i] = _mm256_xor_si256(state[i], _mm256_loadu_si256(rhs.add(i)));
            block_xy[i].write(_mm256_xor_si256(state[i], _mm256_loadu_si256(next.add(i))));
        }
    } else {
        for i in 0..VECS {
            state[i] = _mm256_xor_si256(state[i], _mm256_loadu_si256(rhs.add(i)));
            block_xy[i].write(state[i]);
        }
    }

    for i in 0..4 {
        round_1(state, i);
    }

    for i in 0..4 {
        round_2(state, i);
    }

    for i in 0..VECS {
        state[i] = _mm256_xor_si256(state[i], block_xy[i].assume_init());
        _mm256_storeu_si256(next.add(i), state[i]);
    }
}

/// `BLAKE2_ROUND_1` on rows `2 * i` and `2 * i + 1`.
#[inline(always)]
unsafe fn round_1(s: &mut State, i: usize) {
    // `[A0, A1, B0, B1, C0, C1, D0, D1]` as passed by the reference `fill_block`
    const IDX: [usize; 8] = [0, 4, 1, 5, 2, 6, 3, 7];

    let mut v = IDX.map(|k| s[8 * i + k]);
    g1(&mut v);
    g2(&mut v);
    diagonalize_1(&mut v);
    g1(&mut v);
    g2(&mut v);
    undiagonalize_1(&mut v);

    for (k, x) in IDX.into_iter().zip(v) {
        s[8 * i + k] = x;
    }
}

/// `BLAKE2_ROUND_2` on vectors `i, i + 4, …, i + 28`.
#[inline(always)]
unsafe fn round_2(s: &mut State, i: usize) {
    let mut v: [__m256i; 8] = core::array::from_fn(|j| s[4 * j + i]);
    g1(&mut v);
    g2(&mut v);
    diagonalize_2(&mut v);
    g1(&mut v);
    g2(&mut v);
    undiagonalize_2(&mut v);

    for (j, x) in v.into_iter().enumerate() {
        s[4 * j + i] = x;
    }
}

// Indices into the `[A0, A1, B0, B1, C0, C1, D0, D1]` argument order of the
// reference macros.
const A0: usize = 0;
const A1: usize = 1;
const B0: usize = 2;
const B1: usize = 3;
const C0: usize = 4;
const C1: usize = 5;
const D0: usize = 6;
const D1: usize = 7;

/// `_MM_SHUFFLE(z, y, x, w)` from the C intrinsics headers.
const fn mm_shuffle(z: i32, y: i32, x: i32, w: i32) -> i32 {
    (z << 6) | (y << 4) | (x << 2) | w
}

/// `BlaMka`: `x + y + 2 * lo32(x) * lo32(y)` on each 64-bit lane.
#[inline(always)]
unsafe fn blamka(x: __m256i, y: __m256i) -> __m256i {
    let xy = _mm256_mul_epu32(x, y);
    _mm256_add_epi64(x, _mm256_add_epi64(y, _mm256_add_epi64(xy, xy)))
}

/// Rotate each 64-bit lane right by 32 bits.
#[inline(always)]
unsafe fn rotr32(x: __m256i) -> __m256i {
    _mm256_shuffle_epi32::<{ mm_shuffle(2, 3, 0, 1) }>(x)
}

/// Rotate each 64-bit lane right by 24 bits.
#[inline(always)]
unsafe fn rotr24(x: __m256i) -> __m256i {
    #[rustfmt::skip]
    let mask = _mm256_setr_epi8(
        3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10,
        3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10,
    );
    _mm256_shuffle_epi8(x, mask)
}

/// Rotate each 64-bit lane right by 16 bits.
#[inline(always)]
unsafe fn rotr16(x: __m256i) -> __m256i {
    #[rustfmt::skip]
    let mask = _mm256_setr_epi8(
        2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9,
        2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9,
    );
    _mm256_shuffle_epi8(x, mask)
}

/// Rotate each 64-bit lane right by 63 bits.
#[inline(always)]
unsafe fn rotr63(x: __m256i) -> __m256i {
    _mm256_xor_si256(_mm256_srli_epi64::<63>(x), _mm256_add_epi64(x, x))
}

/// `G1_AVX2`: first half of the `BlaMka` G function.
#[inline(always)]
unsafe fn g1(v: &mut [__m256i; 8]) {
    for (a, b, c, d) in [(A0, B0, C0, D0), (A1, B1, C1, D1)] {
        v[a] = blamka(v[a], v[b]);
        v[d] = rotr32(_mm256_xor_si256(v[d], v[a]));
        v[c] = blamka(v[c], v[d]);
        v[b] = rotr24(_mm256_xor_si256(v[b], v[c]));
    }
}

/// `G2_AVX2`: second half of the `BlaMka` G function.
#[inline(always)]
unsafe fn g2(v: &mut [__m256i; 8]) {
    for (a, b, c, d) in [(A0, B0, C0, D0), (A1, B1, C1, D1)] {
        v[a] = blamka(v[a], v[b]);
        v[d] = rotr16(_mm256_xor_si256(v[d], v[a]));
        v[c] = blamka(v[c], v[d]);
        v[b] = rotr63(_mm256_xor_si256(v[b], v[c]));
    }
}

/// `DIAGONALIZE_1`.
#[inline(always)]
unsafe fn diagonalize_1(v: &mut [__m256i; 8]) {
    for (b, c, d) in [(B0, C0, D0), (B1, C1, D1)] {
        v[b] = _mm256_permute4x64_epi64::<{ mm_shuffle(0, 3, 2, 1) }>(v[b]);
        v[c] = _mm256_permute4x64_epi64::<{ mm_shuffle(1, 0, 3, 2) }>(v[c]);
        v[d] = _mm256_permute4x64_epi64::<{ mm_shuffle(2, 1, 0, 3) }>(v[d]);
    }
}

/// `UNDIAGONALIZE_1`.
#[inline(always)]
unsafe fn undiagonalize_1(v: &mut [__m256i; 8]) {
    for (b, c, d) in [(B0, C0, D0), (B1, C1, D1)] {
        v[b] = _mm256_permute4x64_epi64::<{ mm_shuffle(2, 1, 0, 3) }>(v[b]);
        v[c] = _mm256_permute4x64_epi64::<{ mm_shuffle(1, 0, 3, 2) }>(v[c]);
        v[d] = _mm256_permute4x64_epi64::<{ mm_shuffle(0, 3, 2, 1) }>(v[d]);
    }
}

/// `DIAGONALIZE_2`.
#[inline(always)]
unsafe fn diagonalize_2(v: &mut [__m256i; 8]) {
    const SWAP: i32 = mm_shuffle(2, 3, 0, 1);

    let tmp1 = _mm256_blend_epi32::<0xCC>(v[B0], v[B1]);
    let tmp2 = _mm256_blend_epi32::<0x33>(v[B0], v[B1]);
    v[B1] = _mm256_permute4x64_epi64::<SWAP>(tmp1);
    v[B0] = _mm256_permute4x64_epi64::<SWAP>(tmp2);

    v.swap(C0, C1);

    let tmp1 = _mm256_blend_epi32::<0xCC>(v[D0], v[D1]);
    let tmp2 = _mm256_blend_epi32::<0x33>(v[D0], v[D1]);
    v[D0] = _mm256_permute4x64_epi64::<SWAP>(tmp1);
    v[D1] = _mm256_permute4x64_epi64::<SWAP>(tmp2);
}

/// `UNDIAGONALIZE_2`.
#[inline(always)]
unsafe fn undiagonalize_2(v: &mut [__m256i; 8]) {
    const SWAP: i32 = mm_shuffle(2, 3, 0, 1);

    let tmp1 = _mm256_blend_epi32::<0xCC>(v[B0], v[B1]);
    let tmp2 = _mm256_blend_epi32::<0x33>(v[B0], v[B1]);
    v[B0] = _mm256_permute4x64_epi64::<SWAP>(tmp1);
    v[B1] = _mm256_permute4x64_epi64::<SWAP>(tmp2);

    v.swap(C0, C1);

    let tmp1 = _mm256_blend_epi32::<0x33>(v[D0], v[D1]);
    let tmp2 = _mm256_blend_epi32::<0xCC>(v[D0], v[D1]);
    v[D0] = _mm256_permute4x64_epi64::<SWAP>(tmp1);
    v[D1] = _mm256_permute4x64_epi64::<SWAP>(tmp2);
}
