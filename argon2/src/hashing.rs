//! A hash computed a slice at a time.

use core::fmt;

#[cfg(feature = "parallel")]
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::{
    Argon2, Block, SYNC_POINTS,
    memory::{LaneCounter, SliceView},
};

/// A hash computed a slice at a time, made by [`Argon2::start_hash_password_into`].
///
/// [`Hashing::next_segments`] gives out the slices of the memory one after the other, as the
/// [`Segments`] to compute, one per lane. They can be computed at the same time, by sharing them
/// with other threads or processors, or one at a time, for a caller that does something else in
/// between, such as running an event loop (with [`Segments::work_one`]). Dropping it stops the
/// hash.
///
/// ```
/// # fn main() -> argon2::Result<()> {
/// use argon2::{Argon2, Block};
///
/// let argon2 = Argon2::default();
/// let mut blocks = vec![Block::new(); argon2.params().block_count()];
/// let mut out = [0u8; 32];
/// let mut hashing = argon2.start_hash_password_into(b"password", b"somesalt", &mut out, &mut blocks)?;
/// while let Some(segments) = hashing.next_segments() {
///     std::thread::scope(|s| {
///         for _ in 1..segments.lanes() {
///             s.spawn(|| segments.work());
///         }
///         segments.work();
///     });
/// }
/// # Ok(())
/// # }
/// ```
#[must_use = "the hash is computed by calling `next_segments` until it returns `None`"]
pub struct Hashing<'a> {
    argon2: &'a Argon2<'a>,
    memory: &'a mut [Block],
    /// Taken when the hash is written into it, `None` to only fill the memory.
    out: Option<&'a mut [u8]>,
    pass: usize,
    slice: usize,
    next_lane: LaneCounter,
}

impl<'a> Hashing<'a> {
    pub(crate) fn new(
        argon2: &'a Argon2<'a>,
        memory: &'a mut [Block],
        out: Option<&'a mut [u8]>,
    ) -> Self {
        Hashing {
            argon2,
            memory,
            out,
            pass: 0,
            slice: 0,
            next_lane: LaneCounter::default(),
        }
    }

    /// The segments of the next slice with segments left to compute, or, after the last one,
    /// `None` once the hash is written to `out`. Segments dropped with some left are given out
    /// again: a loop that never computes them never ends.
    ///
    /// # Panics
    /// Never: [`Argon2::start_hash_password_into`] checked the length of `out`, the only thing
    /// that could make writing the hash fail.
    #[must_use]
    pub fn next_segments(&mut self) -> Option<Segments<'_>> {
        let lanes = self.argon2.params().lanes();
        let passes = self.argon2.params().t_cost() as usize;
        // The `Segments` borrowed `self`: every lane taken is done.
        if self.pass < passes && *self.next_lane.get_mut() >= lanes {
            *self.next_lane.get_mut() = 0;
            self.slice += 1;
            if self.slice == SYNC_POINTS {
                self.slice = 0;
                self.pass += 1;
            }
        }
        if self.pass == passes {
            if let Some(out) = self.out.take() {
                self.argon2
                    .finalize(self.memory, out)
                    .expect("the length of `out` was checked at the start");
            }
            return None;
        }
        Some(Segments {
            argon2: self.argon2,
            view: SliceView::new(self.memory, lanes, self.slice, &self.next_lane),
            pass: self.pass,
        })
    }

    /// Computes the rest of the hash on this thread, or with [rayon] with the `parallel` feature.
    pub(crate) fn finish(mut self) {
        while let Some(segments) = self.next_segments() {
            #[cfg(not(feature = "parallel"))]
            segments.work();
            #[cfg(feature = "parallel")]
            (0..segments.lanes())
                .into_par_iter()
                .for_each(|_| segments.work());
        }
    }
}

impl fmt::Debug for Hashing<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hashing")
            .field("pass", &self.pass)
            .field("slice", &self.slice)
            .finish_non_exhaustive()
    }
}

/// The segments of one slice of the Argon2 memory, one per lane (RFC 9106, section 3.4), given out
/// by [`Hashing::next_segments`]: they can be computed at the same time, by threads or other
/// processors sharing a `&Segments` and calling [`Segments::work`]. It's `Sync` on targets with
/// atomics.
///
/// The next slice reads what the workers wrote: they must be done, and their writes visible, when
/// [`Hashing::next_segments`] is called again. Joining scoped threads does that. Workers started some
/// other way, through `unsafe` code, must synchronize with it (with release and acquire orderings).
#[must_use = "the segments are computed by `work` or `work_one`"]
pub struct Segments<'a> {
    argon2: &'a Argon2<'a>,
    view: SliceView<'a>,
    pass: usize,
}

impl Segments<'_> {
    /// The number of lanes: at most as many workers as can be busy.
    #[must_use]
    pub fn lanes(&self) -> usize {
        self.argon2.params().lanes()
    }

    /// Computes the segment of a lane no worker has taken yet: false when none is left.
    #[allow(clippy::must_use_candidate, reason = "called for its work")]
    pub fn work_one(&self) -> bool {
        let Some((lane, segment)) = self.view.take() else {
            return false;
        };
        self.argon2
            .fill_segment(segment, self.pass, self.view.slice, lane);
        true
    }

    /// Computes the segments of the lanes no worker has taken yet, until none is left. Call it
    /// from as many threads at the same time as you like.
    pub fn work(&self) {
        while self.work_one() {}
    }
}

impl fmt::Debug for Segments<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Segments")
            .field("pass", &self.pass)
            .field("slice", &self.view.slice)
            .finish_non_exhaustive()
    }
}
