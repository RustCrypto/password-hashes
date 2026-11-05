//! Block compression backends.
//!
//! - `soft`: portable Rust. It is used on every target.
//! - `avx2`: AVX2 intrinsics on `x86` and `x86_64`. It is selected at runtime
//!   with `cpufeatures`.
//!
//! Build with `RUSTFLAGS='--cfg argon2_backend="soft"'` to always use `soft`.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod avx2;
mod soft;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) use avx2::Avx2;
pub(crate) use soft::Soft;

use crate::Block;

/// Block compression primitives used by the segment fill loop.
///
/// The SIMD implementations are `#[inline(always)]`, so they are compiled with the
/// target features of the function that fills the segment.
pub(crate) trait Compressor: Copy {
    /// Running block state: the backend's own copy of the previous block, if it keeps one.
    type State;

    /// Load a block into a state.
    fn load(self, block: &Block) -> Self::State;

    /// `next = G(prev, rhs)`, or `next ^= G(prev, rhs)` when `with_xor` is set.
    ///
    /// `state` holds the same value as `prev`; a backend may read either. On return,
    /// `state` holds the new value of `next`. This is `fill_block` in the reference
    /// implementation's `opt.c`.
    fn compress(
        self,
        state: &mut Self::State,
        prev: &Block,
        rhs: &Block,
        next: &mut Block,
        with_xor: bool,
    );
}

/// Backend selected for one hash.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Backend {
    /// Portable backend.
    Soft,

    /// AVX2 backend. The value proves that the CPU supports AVX2.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Avx2(Avx2),
}

/// Differential tests: every SIMD backend must give the same output as `soft`.
#[cfg(all(test, any(target_arch = "x86", target_arch = "x86_64")))]
mod tests {
    extern crate std;

    use super::{Avx2, Compressor, Soft};
    use crate::Block;
    use std::eprintln;

    /// `SplitMix64`, a small PRNG with a fixed seed for reproducible tests.
    struct Rng(u64);

    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        /// A value in `lo..=hi`.
        #[cfg(feature = "alloc")]
        #[allow(clippy::cast_possible_truncation)]
        fn range(&mut self, lo: u32, hi: u32) -> u32 {
            lo + (self.next_u64() % u64::from(hi - lo + 1)) as u32
        }

        fn block(&mut self) -> Block {
            let mut block = Block::new();
            for w in block.as_mut() {
                *w = self.next_u64();
            }
            block
        }

        #[cfg(feature = "alloc")]
        #[allow(clippy::cast_possible_truncation)]
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf {
                *b = self.next_u64() as u8;
            }
        }
    }

    /// The AVX2 backend, or `None` (and a note) if the CPU does not support AVX2.
    fn avx2() -> Option<Avx2> {
        if crate::avx2_cpuid::get() {
            // SAFETY: `cpufeatures` detected AVX2.
            Some(unsafe { Avx2::new_unchecked() })
        } else {
            eprintln!("AVX2 not available: skipping AVX2 differential test");
            None
        }
    }

    /// Compress a chain of blocks, as the segment fill loop does, and return all outputs.
    fn compress_chain<C: Compressor>(
        c: C,
        prev: &Block,
        inputs: &[(Block, Block, bool)],
    ) -> [Block; 3] {
        let mut state = c.load(prev);
        let mut prev = *prev;
        let mut outputs = [Block::new(); 3];
        for (out, (rhs, next, with_xor)) in outputs.iter_mut().zip(inputs) {
            *out = *next;
            c.compress(&mut state, &prev, rhs, out, *with_xor);
            prev = *out;
        }
        outputs
    }

    #[test]
    fn avx2_compress_matches_soft() {
        let Some(avx2) = avx2() else { return };
        let mut rng = Rng(0x0A12_60C2);

        for i in 0..10_000 {
            let prev = rng.block();
            let inputs: [(Block, Block, bool); 3] =
                core::array::from_fn(|j| (rng.block(), rng.block(), (i >> j) & 1 == 1));

            let soft = compress_chain(Soft, &prev, &inputs);
            let simd = compress_chain(avx2, &prev, &inputs);
            for (s, v) in soft.iter().zip(&simd) {
                assert_eq!(s.as_ref(), v.as_ref(), "case {i}");
            }
        }
    }

    #[cfg(feature = "alloc")]
    #[allow(clippy::unwrap_used)]
    /// Hash random inputs with both backends and compare the tags.
    ///
    /// `case` cycles through all algorithms, versions, and with/without secret
    /// and associated data (24 combinations).
    fn hash_both(rng: &mut Rng, avx2: Avx2, case: usize, m_cost: u32, t_cost: u32, p_cost: u32) {
        use super::Backend;
        use crate::{Algorithm, Argon2, AssociatedData, Params, ParamsBuilder, Version};
        use alloc::{vec, vec::Vec};

        let algorithm = [Algorithm::Argon2d, Algorithm::Argon2i, Algorithm::Argon2id][case % 3];
        let version = [Version::V0x10, Version::V0x13][case / 3 % 2];
        let output_len = rng.range(4, 64) as usize;

        let mut builder = ParamsBuilder::new();
        builder
            .m_cost(m_cost)
            .t_cost(t_cost)
            .p_cost(p_cost)
            .output_len(output_len);
        if case / 6 % 2 == 1 {
            let mut ad =
                vec![0u8; rng.range(1, u32::try_from(Params::MAX_DATA_LEN).unwrap()) as usize];
            rng.fill(&mut ad);
            builder.data(AssociatedData::new(&ad).unwrap());
        }
        let params = builder.build().unwrap();

        let mut secret = vec![0u8; rng.range(1, 64) as usize];
        rng.fill(&mut secret);
        let argon2 = if case / 12 % 2 == 1 {
            Argon2::new_with_secret(&secret, algorithm, version, params.clone()).unwrap()
        } else {
            Argon2::new(algorithm, version, params.clone())
        };

        let mut pwd = vec![0u8; rng.range(0, 64) as usize];
        rng.fill(&mut pwd);
        let mut salt = vec![0u8; rng.range(8, 32) as usize];
        rng.fill(&mut salt);

        let mut outputs = Vec::new();
        for backend in [Backend::Soft, Backend::Avx2(avx2)] {
            let mut memory = vec![Block::new(); params.block_count()];
            let mut out = vec![0u8; output_len];
            argon2
                .hash_password_into_with_backend(&pwd, &salt, &mut out, &mut memory, backend)
                .unwrap();
            outputs.push(out);
        }
        assert_eq!(
            outputs[0], outputs[1],
            "{algorithm:?} {version:?} m={m_cost} t={t_cost} p={p_cost}"
        );
    }

    /// Random inputs over m (minimum to 4 MiB), t (1-5), p (1-4), all
    /// algorithms and versions, with and without secret and associated data.
    #[cfg(feature = "alloc")]
    #[test]
    fn avx2_hash_matches_soft_random() {
        let Some(avx2) = avx2() else { return };
        let mut rng = Rng(0x005E_EDA2);

        for case in 0..240 {
            let p_cost = rng.range(1, 4);
            let m_cost = rng.range(8 * p_cost, 4096);
            let t_cost = rng.range(1, 5);
            hash_both(&mut rng, avx2, case, m_cost, t_cost, p_cost);
        }
    }

    /// Every t and p at the minimum m, each with all 24 `case` combinations.
    #[cfg(feature = "alloc")]
    #[test]
    fn avx2_hash_matches_soft_min_memory() {
        let Some(avx2) = avx2() else { return };
        let mut rng = Rng(0x0000_01A2);

        for t_cost in 1..=5 {
            for p_cost in 1..=4 {
                for case in 0..24 {
                    hash_both(&mut rng, avx2, case, 8 * p_cost, t_cost, p_cost);
                }
            }
        }
    }
}
