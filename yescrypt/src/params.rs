//! Algorithm parameters.

bitflags::bitflags! {
    /// Flags for controlling the operation of `yescrypt`.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Flags: u32 {
        const WORM                = 0x001;
        const RW                  = 0x002;
        const ROUNDS_3            = 0b000;
        const ROUNDS_6            = 0x004;
        const GATHER_4            = 0x010;
        const SIMPLE_2            = 0x020;
        const SBOX_12K            = 0x080;
        const SHARED_PREALLOCATED = 0x10000;
        const MODE_MASK           = 0x3;
        const RW_FLAVOR_MASK      = 0x3fc;
        const INIT_SHARED         = 0x01000000;
        const ALLOC_ONLY          = 0x08000000;
        const PREHASH             = 0x10000000;
    }
}

impl Default for Flags {
    fn default() -> Self {
        // Adapted from upstream reference C's `YESCRYPT_RW_DEFAULTS`
        Flags::RW | Flags::ROUNDS_6 | Flags::GATHER_4 | Flags::SIMPLE_2 | Flags::SBOX_12K
    }
}

/// `yescrypt` parameters.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Params {
    /// Flags which provide fine-grained behavior control.
    pub flags: Flags,

    /// `N`: CPU/memory cost (like `scrypt`).
    pub n: u64,

    /// `r`: block size (like `scrypt`).
    pub r: u32,

    /// `p`: parallelism (like `scrypt`).
    pub p: u32,

    /// special to yescrypt.
    pub t: u32,

    /// special to yescrypt.
    pub g: u32,

    /// special to yescrypt.
    pub nrom: u64,
}

impl Params {
    /// Initialize params.
    pub fn new(flags: Flags, n: u64, r: u32, p: u32, t: u32, g: u32) -> Params {
        Params {
            flags,
            n,
            r,
            p,
            t,
            g,
            nrom: 0,
        }
    }
}

impl Default for Params {
    // From the upstream C reference implementation's `PARAMETERS` file:
    //
    // > Large and slow (memory usage 16 MiB, performance like bcrypt cost 2^8 -
    // > latency 10-30 ms and throughput 1000+ per second on a 16-core server)
    fn default() -> Self {
        // flags = YESCRYPT_DEFAULTS, N = 4096, r = 32, p = 1, t = 0, g = 0, NROM = 0
        Params {
            flags: Flags::default(),
            n: 4096,
            r: 32,
            p: 1,
            t: 0,
            g: 0,
            nrom: 0,
        }
    }
}
