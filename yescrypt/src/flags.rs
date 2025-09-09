//! Algorithm flags.

use crate::{Error, Result};
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign};

/// Mode mask value
const MODE_MASK: u32 = 0x3;

/// Read/write flavor mask value
const RW_FLAVOR_MASK: u32 = 0x3fc;

/// Flags for selecting the "flavor" of `yescrypt`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Flags(pub(crate) u32);

impl Flags {
    /// Empty flags (represents `scrypt` classic mode)
    pub const EMPTY: Self = Self(0);

    /// Mode: write once, read many
    pub const WORM: Self = Self(0x001);

    /// Mode: read/write
    pub const RW: Self = Self(0x002);

    /// Flavor: 6 rounds
    pub const ROUNDS_6: Self = Self(0x004);

    /// Flavor: gather 4
    pub const GATHER_4: Self = Self(0x010);

    /// Flavor: simple 2
    pub const SIMPLE_2: Self = Self(0x020);

    /// Flavor: SBox 12k
    pub const SBOX_12K: Self = Self(0x080);

    /// Prehash
    pub(crate) const PREHASH: Self = Self(0x10000000);

    /// All possible flags.
    // Notably this only includes flags in the public API
    const ALL_FLAGS: Self = Self(
        Self::WORM.0
            | Self::RW.0
            | Self::ROUNDS_6.0
            | Self::GATHER_4.0
            | Self::SIMPLE_2.0
            | Self::SBOX_12K.0,
    );

    /// Get the raw bits used to encode the flags.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Create flags from raw bits.
    pub const fn from_bits(bits: u32) -> Result<Self> {
        // Check for any bits outside the allowed range.
        if bits & !Self::ALL_FLAGS.0 != 0 {
            return Err(Error::Params);
        }

        Ok(Self(bits))
    }

    /// Are any flags set?
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Is the prehash bit set?
    pub(crate) fn has_prehash(self) -> bool {
        self.0 & Flags::PREHASH.0 != 0
    }

    /// Is the read-write bit set?
    pub(crate) fn has_rw(self) -> bool {
        self.0 & Flags::RW.0 != 0
    }

    /// Clear the given flag bits.
    pub(crate) fn clear(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Get the mode based on the mode mask.
    pub(crate) fn mode(self) -> Result<Mode> {
        match Flags(self.0 & MODE_MASK) {
            Flags(0) => Ok(Mode::Classic),
            Self::WORM => Ok(Mode::Worm),
            Self::RW => Ok(Mode::Rw {
                flavor_bits: self.0 & RW_FLAVOR_MASK,
            }),
            _ => Err(Error::Params),
        }
    }

    /// Compute a `u32` representing the "flavor" of yescrypt to be encoded into the params string.
    pub(crate) fn flavor(self) -> Result<u32> {
        if self.0 < Flags::RW.0 {
            Ok(self.0)
        } else if (self.0 & MODE_MASK) == Flags::RW.0 && self.0 <= (Flags::RW.0 | RW_FLAVOR_MASK) {
            Ok(Flags::RW.0 + (self.0 >> 2))
        } else {
            Err(Error::Params)
        }
    }

    /// Decode flags from a "flavor" represented by a `u32` as encoded in a params string.
    pub(crate) fn from_flavor(flavor: u32) -> Result<Self> {
        if flavor < Flags::RW.0 {
            Self::from_bits(flavor)
        } else if flavor <= Flags::RW.0 + (RW_FLAVOR_MASK >> 2) {
            Self::from_bits(Flags::RW.0 + ((flavor - Flags::RW.0) << 2))
        } else {
            Err(Error::Params)
        }
    }
}

impl Default for Flags {
    fn default() -> Self {
        // Adapted from upstream reference C's `YESCRYPT_RW_DEFAULTS`
        Flags::RW | Flags::ROUNDS_6 | Flags::GATHER_4 | Flags::SIMPLE_2 | Flags::SBOX_12K
    }
}

impl BitAnd for Flags {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for Flags {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl BitOr for Flags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for Flags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// yescrypt modes
pub(crate) enum Mode {
    /// classic scrypt
    Classic,

    /// write once, read many
    Worm,

    /// read-write
    Rw {
        /// flavor of yescrypt, e.g. `ROUNDS_6`, `GATHER_4`, `SIMPLE_2`, `SBOX_12K`
        flavor_bits: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::Flags;

    #[test]
    fn flavor() {
        assert_eq!(Flags::EMPTY.flavor().unwrap(), 0);
        assert_eq!(Flags::WORM.flavor().unwrap(), 1);
        assert_eq!(Flags::default().flavor().unwrap(), 0b101111);
    }

    #[test]
    fn from_flavor() {
        assert_eq!(Flags::from_flavor(0).unwrap(), Flags::EMPTY);
        assert_eq!(Flags::from_flavor(1).unwrap(), Flags::WORM);
        assert_eq!(Flags::from_flavor(0b101111).unwrap(), Flags::default());
    }
}
