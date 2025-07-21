//! Views into Argon2 memory that can be processed in parallel.
//!
//! This module implements, with a combination of compile-time borrowing and runtime checking, the
//! cooperative contract described in section 3.4 (Indexing) of RFC 9106:
//!
//! > To enable parallel block computation, we further partition the memory matrix into SL = 4
//! > vertical slices. The intersection of a slice and a lane is called a segment, which has a
//! > length of q/SL. Segments of the same slice can be computed in parallel and do not reference
//! > blocks from each other. All other blocks can be referenced.

use core::marker::PhantomData;
use core::ptr::NonNull;

#[cfg(feature = "parallel")]
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::{Block, SYNC_POINTS};

/// Extension trait for Argon2 memory blocks.
pub(crate) trait Memory<'a> {
    /// Compute each Argon2 segment.
    ///
    /// By default computation is single threaded. Parallel computation can be enabled with the
    /// `parallel` feature, in which case [rayon] is used to compute as many lanes in parallel as
    /// possible.
    fn for_each_segment<F>(&mut self, lanes: usize, f: F)
    where
        F: Fn(SegmentView<'_>, usize, usize) + Sync + Send;
}

impl Memory<'_> for &mut [Block] {
    #[cfg(not(feature = "parallel"))]
    fn for_each_segment<F>(&mut self, lanes: usize, f: F)
    where
        F: Fn(SegmentView<'_>, usize, usize) + Sync + Send,
    {
        let inner = MemoryInner::new(self, lanes);
        for slice in 0..SYNC_POINTS {
            for lane in 0..lanes {
                // SAFETY: `self` exclusively borrows the blocks, and we sequentially process
                // slices and segments.
                let segment = unsafe { SegmentView::new(inner, slice, lane) };
                f(segment, slice, lane);
            }
        }
    }

    #[cfg(feature = "parallel")]
    fn for_each_segment<F>(&mut self, lanes: usize, f: F)
    where
        F: Fn(SegmentView<'_>, usize, usize) + Sync + Send,
    {
        let inner = MemoryInner::new(self, lanes);
        for slice in 0..SYNC_POINTS {
            (0..lanes).into_par_iter().for_each(|lane| {
                // SAFETY: `self` exclusively borrows the blocks, we sequentially process slices,
                // and we create exactly one segment view per lane in a slice.
                let segment = unsafe { SegmentView::new(inner, slice, lane) };
                f(segment, slice, lane);
            });
        }
    }
}

/// Low-level pointer and metadata for an Argon2 memory region.
#[derive(Clone, Copy)]
struct MemoryInner<'a> {
    blocks: NonNull<Block>,
    block_count: usize,
    lane_length: usize,
    phantom: PhantomData<&'a mut Block>,
}

impl MemoryInner<'_> {
    fn new(memory_blocks: &mut [Block], lanes: usize) -> Self {
        let block_count = memory_blocks.len();
        let lane_length = block_count / lanes;

        // SAFETY: the pointer needs to be derived from a mutable reference because (later)
        // mutating the blocks through a pointer derived from a shared reference would be UB.
        let blocks = NonNull::from(memory_blocks);

        MemoryInner {
            blocks: blocks.cast(),
            block_count,
            lane_length,
            phantom: PhantomData,
        }
    }

    fn lane_of(&self, index: usize) -> usize {
        index / self.lane_length
    }

    fn slice_of(&self, index: usize) -> usize {
        index / (self.lane_length / SYNC_POINTS) % SYNC_POINTS
    }
}

// SAFETY: private type, and just a pointer with some metadata.
unsafe impl Send for MemoryInner<'_> {}

// SAFETY: private type, and just a pointer with some metadata.
unsafe impl Sync for MemoryInner<'_> {}

/// A view into Argon2 memory for a particular segment (i.e. slice × lane).
pub(crate) struct SegmentView<'a> {
    inner: MemoryInner<'a>,
    slice: usize,
    lane: usize,
}

impl<'a> SegmentView<'a> {
    /// Create a view into Argon2 memory for a particular segment (i.e. slice × lane).
    ///
    /// # Safety
    ///
    /// At any time, there can be at most one view for a given Argon2 segment. Additionally, all
    /// concurrent segment views must be for the same slice.
    unsafe fn new(inner: MemoryInner<'a>, slice: usize, lane: usize) -> Self {
        SegmentView { inner, slice, lane }
    }

    /// Get a shared reference to a block.
    ///
    /// # Panics
    ///
    /// Panics if the index is out of bounds or if the desired block *could* be mutably aliased (if
    /// it is on the current slice but on a different lane/segment).
    pub fn get_block(&self, index: usize) -> &Block {
        assert!(index < self.inner.block_count);
        assert!(self.inner.lane_of(index) == self.lane || self.inner.slice_of(index) != self.slice);

        // SAFETY: by construction, the base pointer is valid for reads, and we assert that the
        // index is in bounds. We also assert that the index either lies on this lane, or is on
        // another slice. Finally, we're the only view into this segment, and mutating through it
        // requires `&mut self` and is restricted to blocks within the segment.
        unsafe { self.inner.blocks.add(index).as_ref() }
    }

    /// Get a mutable reference to a block.
    ///
    /// # Panics
    ///
    /// Panics if the index is out of bounds or if the desired block lies outside this segment.
    pub fn get_block_mut(&mut self, index: usize) -> &mut Block {
        assert!(index < self.inner.block_count);
        assert_eq!(self.inner.lane_of(index), self.lane);
        assert_eq!(self.inner.slice_of(index), self.slice);

        // SAFETY: by construction, the base pointer is valid for reads and writes, and we assert
        // that the index is in bounds. We also assert that the index lies on this segment, and
        // we're the only view for it, taking `&mut self`.
        unsafe { self.inner.blocks.add(index).as_mut() }
    }
}
