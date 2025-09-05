//! Algorithm parameters.

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

        /// Use shared preallocated memory
        const SHARED_PREALLOCATED = 0x10000;

        /// Mode mask value
        const MODE_MASK = 0x3;

        /// Read/write flavor mask value
        const RW_FLAVOR_MASK = 0x3fc;

        /// Initialize shared memory
        const INIT_SHARED = 0x01000000;

        /// Allocate only
        const ALLOC_ONLY = 0x08000000;

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

/// `yescrypt` algorithm parameters.
///
/// These are various algorithm settings which can control e.g. the amount of resource utilization.
#[derive(Clone, Copy, Debug)]
pub struct Params {
    /// Flags which provide fine-grained behavior control.
    pub(crate) flags: Flags,

    /// `N`: CPU/memory cost (like `scrypt`).
    pub(crate) n: u64,

    /// `r`: block size (like `scrypt`).
    pub(crate) r: u32,

    /// `p`: parallelism (like `scrypt`).
    pub(crate) p: u32,

    /// special to yescrypt.
    pub(crate) t: u32,

    /// special to yescrypt.
    pub(crate) g: u32,

    /// special to yescrypt.
    pub(crate) nrom: u64,
}

impl Params {
    /// Initialize params.
    pub const fn new(flags: Flags, n: u64, r: u32, p: u32) -> Params {
        Self::new_with_all_params(flags, n, r, p, 0, 0)
    }

    /// Initialize params.
    pub const fn new_with_all_params(
        flags: Flags,
        n: u64,
        r: u32,
        p: u32,
        t: u32,
        g: u32,
    ) -> Params {
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

    /// `N`: CPU/memory cost (like `scrypt`).
    ///
    /// Memory and CPU usage scale linearly with `N`.
    pub const fn n(&self) -> u64 {
        self.n
    }

    /// `r` parameter: resource usage (like `scrypt`).
    ///
    /// Memory and CPU usage scales linearly with this parameter.
    pub const fn r(&self) -> u32 {
        self.r
    }

    /// `p` parameter: parallelization (like `scrypt`).
    pub const fn p(&self) -> u32 {
        self.p
    }
}

impl Default for Params {
    // From the upstream C reference implementation's `PARAMETERS` file:
    //
    // > Large and slow (memory usage 16 MiB, performance like bcrypt cost 2^8 -
    // > latency 10-30 ms and throughput 1000+ per second on a 16-core server)
    fn default() -> Self {
        // flags = YESCRYPT_DEFAULTS, N = 4096, r = 32, p = 1, t = 0, g = 0, NROM = 0
        Params::new(Flags::default(), 4096, 32, 1)
    }
}
