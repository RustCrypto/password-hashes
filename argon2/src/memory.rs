//! Memory blocks

use crate::Block;

/// Structure containing references to the memory blocks
pub(crate) struct Memory<'a> {
    /// Memory blocks
    data: &'a mut [Block],

    /// Size of the memory in blocks
    size: usize,
}

impl<'a> Memory<'a> {
    /// Instantiate a new memory struct
    pub(crate) fn new(data: &'a mut [Block]) -> Self {
        let size = data.len();

        Self { data, size }
    }

    /// Get a copy of the block
    pub(crate) fn get_block(&self, idx: usize) -> Block {
        self.data[idx]
    }

    /// Get a mutable reference to the block
    pub(crate) fn get_block_mut(&mut self, idx: usize) -> &mut Block {
        &mut self.data[idx]
    }

    /// Size of the memory
    pub(crate) fn len(&self) -> usize {
        self.size
    }
}
