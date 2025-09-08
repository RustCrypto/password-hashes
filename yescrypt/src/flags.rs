//! Algorithm flags.

bitflags::bitflags! {
    /// Flags for controlling the operation of `yescrypt`.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Flags: u32 {
        /// Write once read many
        const WORM = 0x001;

        /// Read/write
        const RW = 0x002;

        /// 3 rounds
        const ROUNDS_3 = 0b000;

        /// 6 rounds
        const ROUNDS_6 = 0x004;

        /// Gather 4
        const GATHER_4 = 0x010;

        /// Simple 2
        const SIMPLE_2 = 0x020;

        /// SBox 12k
        const SBOX_12K = 0x080;

        /// Mode mask value
        const MODE_MASK = 0x3;

        /// Read/write flavor mask value
        const RW_FLAVOR_MASK = 0x3fc;

        /// Prehash
        const PREHASH = 0x10000000;
    }
}

impl Default for Flags {
    fn default() -> Self {
        // Adapted from upstream reference C's `YESCRYPT_RW_DEFAULTS`
        Flags::RW | Flags::ROUNDS_6 | Flags::GATHER_4 | Flags::SIMPLE_2 | Flags::SBOX_12K
    }
}
