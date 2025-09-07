//! Utility functions.

use core::{ops::BitXorAssign, slice};
use sha2::Sha256;

pub(crate) fn xor<T>(dst: &mut [T], src: &[T])
where
    T: BitXorAssign + Copy,
{
    assert_eq!(dst.len(), src.len());
    for (dst, src) in core::iter::zip(dst, src) {
        *dst ^= *src
    }
}

pub(crate) fn cast_slice(input: &[u32]) -> &[u8] {
    let new_len = input
        .len()
        .checked_mul(size_of::<u32>() / size_of::<u8>())
        .unwrap();

    // SAFETY: `new_len` accounts for the size difference between the two types
    unsafe { slice::from_raw_parts(input.as_ptr().cast(), new_len) }
}

pub(crate) fn cast_slice_mut(input: &mut [u32]) -> &mut [u8] {
    let new_len = input
        .len()
        .checked_mul(size_of::<u32>() / size_of::<u8>())
        .unwrap();

    // SAFETY: `new_len` accounts for the size difference between the two types
    unsafe { slice::from_raw_parts_mut(input.as_mut_ptr().cast(), new_len) }
}

pub(crate) fn hmac_sha256(key: &[u8], in_0: &[u8]) -> [u8; 32] {
    use hmac::{KeyInit, Mac};

    let mut hmac = hmac::Hmac::<Sha256>::new_from_slice(key)
        .expect("key length should always be valid with hmac");
    hmac.update(in_0);
    hmac.finalize().into_bytes().into()
}

// TODO(tarcieri): use upstream `[T]::as_chunks_mut` when MSRV is 1.88
#[inline]
#[must_use]
pub(crate) fn slice_as_chunks_mut<T, const N: usize>(slice: &mut [T]) -> (&mut [[T; N]], &mut [T]) {
    assert!(N != 0, "chunk size must be non-zero");
    let len_rounded_down = slice.len() / N * N;
    // SAFETY: The rounded-down value is always the same or smaller than the
    // original length, and thus must be in-bounds of the slice.
    let (multiple_of_n, remainder) = unsafe { slice.split_at_mut_unchecked(len_rounded_down) };
    // SAFETY: We already panicked for zero, and ensured by construction
    // that the length of the subslice is a multiple of N.
    let array_slice = unsafe { slice_as_chunks_unchecked_mut(multiple_of_n) };
    (array_slice, remainder)
}

#[inline]
#[must_use]
unsafe fn slice_as_chunks_unchecked_mut<T, const N: usize>(slice: &mut [T]) -> &mut [[T; N]] {
    assert!(
        N != 0 && slice.len() % N == 0,
        "slice::as_chunks_unchecked requires `N != 0` and the slice to split exactly into `N`-element chunks"
    );

    let new_len = slice.len() / N;
    // SAFETY: We cast a slice of `new_len * N` elements into
    // a slice of `new_len` many `N` elements chunks.
    unsafe { slice::from_raw_parts_mut(slice.as_mut_ptr().cast(), new_len) }
}
