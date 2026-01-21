//! yescrypt modes.

use crate::{Error, Result};

// Bits which represent the "flavor" of yescrypt when using `Mode::Rw`
const ROUNDS_6: u32 = 0b000001;
const GATHER_4: u32 = 0b000100;
const SIMPLE_2: u32 = 0b001000;
const SBOX_12K: u32 = 0b100000;

// Bits representing the RW "flavor"
// TODO(tarcieri): support other flavors of yescrypt?
const RW_FLAVOR: u32 = 2 | ROUNDS_6 | GATHER_4 | SIMPLE_2 | SBOX_12K;

/// yescrypt modes: various ways yescrypt can operate.
///
/// [`Mode::default`] (`Rw`) is recommended.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u32)]
pub enum Mode {
    /// classic scrypt: yescrypt is a superset of scrypt.
    Classic = 0,

    /// write-once/read-many: conservative enhancement of classic scrypt.
    Worm = 1,

    /// yescrypt’s native mode: read-write (recommended/default).
    #[default]
    Rw = RW_FLAVOR,
}

impl Mode {
    /// Is the mode scrypt classic?
    pub fn is_classic(self) -> bool {
        self == Self::Classic
    }

    /// Is the mode write-once/read-many?
    pub fn is_worm(self) -> bool {
        self == Self::Worm
    }

    /// Is the mode the yescrypt native read-write mode? (default)
    pub fn is_rw(self) -> bool {
        self == Self::Rw
    }
}

impl TryFrom<u32> for Mode {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Mode::Classic),
            1 => Ok(Mode::Worm),
            RW_FLAVOR => Ok(Mode::Rw),
            _ => Err(Error::Params),
        }
    }
}

impl From<Mode> for u32 {
    fn from(mode: Mode) -> u32 {
        mode as u32
    }
}

#[cfg(test)]
mod tests {
    use super::Mode;

    #[test]
    fn flavor() {
        assert_eq!(0u32, Mode::Classic.into());
        assert_eq!(1u32, Mode::Worm.into());
        assert_eq!(0b101111u32, Mode::default().into());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn try_from() {
        assert_eq!(Mode::try_from(0).unwrap(), Mode::Classic);
        assert_eq!(Mode::try_from(1).unwrap(), Mode::Worm);
        assert_eq!(Mode::try_from(0b101111).unwrap(), Mode::Rw);
    }
}
