//! Portable block compression, using [`Block::compress`].

use super::Compressor;
use crate::Block;

/// Portable backend. It keeps no state and reads the previous block from memory.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Soft;

impl Compressor for Soft {
    type State = ();

    #[inline(always)]
    fn load(self, _block: &Block) {}

    #[inline(always)]
    fn compress(
        self,
        _state: &mut (),
        prev: &Block,
        rhs: &Block,
        next: &mut Block,
        with_xor: bool,
    ) {
        compress(prev, rhs, next, with_xor);
    }
}

/// See [`Compressor::compress`].
///
/// This is not inlined into the segment loop, which keeps the call structure (and
/// the instruction count) of the code before the backends existed.
#[inline(never)]
fn compress(prev: &Block, rhs: &Block, next: &mut Block, with_xor: bool) {
    let result = Block::compress(prev, rhs);

    if with_xor {
        *next ^= &result;
    } else {
        *next = result;
    }
}
