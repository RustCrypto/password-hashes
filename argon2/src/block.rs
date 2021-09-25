//! Argon2 memory block functions

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Structure for the (1 KiB) memory block implemented as 128 64-bit words.
#[derive(Copy, Clone, Debug)]
pub struct Block([u64; Self::SIZE / 8]);

impl Default for Block {
    fn default() -> Self {
        Self([0u64; Self::SIZE / 8])
    }
}

impl Block {
    /// Memory block size in bytes
    pub const SIZE: usize = 1024;
}

#[cfg(feature = "zeroize")]
impl Zeroize for Block {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
