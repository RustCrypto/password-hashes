//! Views into Argon2 memory that can be processed in parallel.
//!
//! This module implements, with a combination of compile-time borrowing and runtime checking, the
//! cooperative contract described in section 3.4 (Indexing) of RFC 9106:
//!
//! > To enable parallel block computation, we further partition the memory matrix into SL = 4
//! > vertical slices. The intersection of a slice and a lane is called a segment, which has a
//! > length of q/SL. Segments of the same slice can be computed in parallel and do not reference
//! > blocks from each other. All other blocks can be referenced.

#![warn(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    unsafe_op_in_unsafe_fn
)]

use core::marker::PhantomData;
use core::ptr::NonNull;

#[cfg(feature = "parallel")]
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::{Block, SYNC_POINTS};

pub trait SegmentViews<'a> {
    /// Construct an iterator of parallelizable views into a set of Argon2 memory blocks.
    ///
    /// If the `parallel` feature is enabled, the returned type implements
    /// [`rayon::iter::ParallelIterator`]; otherwise it implements [`core::iter::Iterator`].
    fn segment_views(&mut self, slice: usize, lanes: usize) -> SegmentViewIter<'_>;
}

impl<'a> SegmentViews<'a> for &'a mut [Block] {
    fn segment_views(&mut self, slice: usize, lanes: usize) -> SegmentViewIter<'_> {
        // The pointer needs to be derived from a mutable reference because (later) mutating the
        // blocks through a pointer derived from a shared reference would be UB.
        let blocks = NonNull::from(&mut **self);
        // SAFETY: we take `&mut self` and any views derived from the returned iterator carry this
        // mutable borrow. Therefore, it's impossible to create a `MemoryViewIter` while another
        // one, or any views derived from it, still exist. Additionally, the pointer and number of
        // blocks are created from `self`.
        unsafe { SegmentViewIter::new(blocks.cast(), self.len(), slice, lanes) }
    }
}

/// Iterator of parallelizable views into a set of Argon2 memory blocks.
pub struct SegmentViewIter<'a> {
    inner: SegmentViewInner<'a>,
    #[cfg(not(feature = "parallel"))]
    minted: usize,
}

impl SegmentViewIter<'_> {
    /// Construct an Iterator of parallelizable views into a set of Argon2 memory blocks.
    ///
    /// # Safety
    ///
    /// `blocks` must point to the start of a Rust slice buffer with `block_count` blocks, and
    /// there currently are no views or view iterators into that memory region.
    unsafe fn new(blocks: NonNull<Block>, block_count: usize, slice: usize, lanes: usize) -> Self {
        // SAFETY: the pointer is valid and there currently are no views into the memory region.
        let inner = unsafe { SegmentViewInner::new(blocks, block_count, slice, lanes) };
        SegmentViewIter {
            inner,
            #[cfg(not(feature = "parallel"))]
            minted: 0,
        }
    }
}

#[cfg(not(feature = "parallel"))]
impl<'a> Iterator for SegmentViewIter<'a> {
    type Item = SegmentView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.minted < self.inner.lanes {
            // SAFETY: `self` mutably borrows the underlying memory region for a single Argon2
            // slice, and we create exactly one memory view per lane.
            let view = unsafe { SegmentView::new(self.inner.unsafe_copy(), self.minted) };
            self.minted += 1;
            Some(view)
        } else {
            None
        }
    }
}

#[cfg(feature = "parallel")]
impl<'a> ParallelIterator for SegmentViewIter<'a> {
    type Item = SegmentView<'a>;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: rayon::iter::plumbing::UnindexedConsumer<Self::Item>,
    {
        (0..self.inner.lanes)
            .into_par_iter()
            .map(|lane| {
                // SAFETY: `self` mutably borrows the underlying memory region for a single Argon2
                // slice, and we create exactly one memory view per lane.
                unsafe { SegmentView::new(self.inner.unsafe_copy(), lane) }
            })
            .drive_unindexed(consumer)
    }
}

/// A view into an Argon2 memory region for a particular Argon2 slice and lane.
pub struct SegmentView<'a> {
    inner: SegmentViewInner<'a>,
    lane: usize,
}

impl<'a> SegmentView<'a> {
    /// Create a new segment view into Argon2 memory.
    ///
    /// # Safety
    ///
    /// There can simultaneously exist at most one view per lane into the same memory region, and
    /// all of them must refer to the same Argon2 slice.
    unsafe fn new(inner: SegmentViewInner<'a>, lane: usize) -> Self {
        Self { inner, lane }
    }
}

impl SegmentView<'_> {
    pub fn get_block(&self, index: usize) -> &Block {
        assert!(index < self.inner.block_count);
        assert!(
            index / self.lane_length() == self.lane
                || index % self.lane_length() / self.segment_length() != self.inner.slice
        );

        // SAFETY: constructing `self` required the pointer to be valid, and `index` is in bounds.
        let ptr = unsafe { self.inner.blocks.add(index) };
        // SAFETY: constructing `self` required that this be the only segment view for this lane,
        // and that no segment views exist for other Argon2 slices. We check that `index` is is
        // either on this lane -- in which case there is mutable aliasing because `get_block_mut`
        // takes `&mut self` -- or on a different Argon2 slice -- in which case there are no
        // mutable references to it at all.
        unsafe { ptr.as_ref() }
    }

    pub fn get_block_mut(&mut self, index: usize) -> &mut Block {
        assert!(index < self.inner.block_count);
        assert!(index / self.lane_length() == self.lane);

        // SAFETY: constructing `self` required the pointer to be valid, and `index` is in bounds.
        let mut ptr = unsafe { self.inner.blocks.add(index) };
        // SAFETY: constructing `self` required this be the only segment view for this lane, and
        // that no segment views exist for other Argon2 slices. We check that `index` is on this
        // lane, and there is no aliasing because we take `&mut self`.
        unsafe { ptr.as_mut() }
    }

    pub fn block_count(&self) -> usize {
        self.inner.block_count
    }

    pub fn lane(&self) -> usize {
        self.lane
    }

    fn lane_length(&self) -> usize {
        self.inner.block_count / self.inner.lanes
    }

    fn segment_length(&self) -> usize {
        self.inner.block_count / self.inner.lanes / SYNC_POINTS
    }
}

/// Underlying pointer and associated data for segment views (and view iterators).
struct SegmentViewInner<'a> {
    blocks: NonNull<Block>,
    block_count: usize,
    slice: usize,
    lanes: usize,
    phantom: PhantomData<&'a mut Block>,
}

// SAFETY: this is a private type, and `SegmentView` enforces the aliasing rules at runtime.
unsafe impl Send for SegmentViewInner<'_> {}
// SAFETY: this is a private type, and `SegmentView` enforces the aliasing rules at runtime.
unsafe impl Sync for SegmentViewInner<'_> {}

impl SegmentViewInner<'_> {
    /// Wrap the underlying pointer and associated data for a segment view.
    ///
    /// # Safety
    ///
    /// This method must not be called in a way that causes memory views to mutably alias.
    /// Additionally, `blocks` must point to the start of a Rust slice buffer with `block_count` blocks.
    unsafe fn new(blocks: NonNull<Block>, block_count: usize, slice: usize, lanes: usize) -> Self {
        Self {
            blocks,
            block_count,
            slice,
            lanes,
            phantom: PhantomData,
        }
    }

    /// Copy the underlying pointer and associated data.
    ///
    /// # Safety
    ///
    /// This method must not be called in a way that causes memory views to mutably alias.
    unsafe fn unsafe_copy(&self) -> Self {
        Self { ..*self }
    }
}
