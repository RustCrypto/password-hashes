//! Views into Argon2 memory that can be processed in parallel.
//!
//! This module implements, with a combination of compile-time borrowing and runtime checking, the
//! cooperative contract described in section 3.4 (Indexing) of RFC 9106:
//!
//! > To enable parallel block computation, we further partition the memory matrix into SL = 4
//! > vertical slices. The intersection of a slice and a lane is called a segment, which has a
//! > length of q/SL. Segments of the same slice can be computed in parallel and do not reference
//! > blocks from each other. All other blocks can be referenced.

#![allow(clippy::unnecessary_safety_comment)]

use core::marker::PhantomData;
use core::ptr::NonNull;

#[cfg(not(target_has_atomic = "ptr"))]
use core::cell::Cell;
#[cfg(target_has_atomic = "ptr")]
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::{Block, SYNC_POINTS};

/// The next lane of a slice to give out: atomic where the target has atomics, so that the lanes
/// can be computed on several threads.
#[derive(Default)]
pub(crate) struct LaneCounter(
    #[cfg(target_has_atomic = "ptr")] AtomicUsize,
    #[cfg(not(target_has_atomic = "ptr"))] Cell<usize>,
);

impl LaneCounter {
    /// The next lane, then the one after…, past the lanes once they're all taken.
    fn take(&self) -> usize {
        #[cfg(target_has_atomic = "ptr")]
        return self.0.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(target_has_atomic = "ptr"))]
        return self.0.replace(self.0.get() + 1);
    }

    pub(crate) fn get_mut(&mut self) -> &mut usize {
        self.0.get_mut()
    }
}

/// One slice of the memory, which gives out a view of each of its segments once.
pub(crate) struct SliceView<'a> {
    inner: MemoryInner<'a>,
    pub(crate) slice: usize,
    lanes: usize,
    next_lane: &'a LaneCounter,
}

impl<'a> SliceView<'a> {
    pub(crate) fn new(
        memory_blocks: &'a mut [Block],
        lanes: usize,
        slice: usize,
        next_lane: &'a LaneCounter,
    ) -> Self {
        SliceView {
            inner: MemoryInner::new(memory_blocks, lanes),
            slice,
            lanes,
            next_lane,
        }
    }

    /// The view of a segment not given out yet, with its lane.
    pub(crate) fn take(&self) -> Option<(usize, SegmentView<'_>)> {
        let lane = self.next_lane.take();
        if lane >= self.lanes {
            return None;
        }
        // SAFETY: `self` exclusively borrows the blocks, all its views are of the same slice, and
        // each lane is given out once.
        Some((lane, unsafe {
            SegmentView::new(self.inner, self.slice, lane)
        }))
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
