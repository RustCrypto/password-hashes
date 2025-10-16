/// Block size for SHA256
pub const BLOCK_SIZE_SHA256: usize = 32;

/// Block size for SHA512
pub const BLOCK_SIZE_SHA512: usize = 64;

/// PWD part length of the password string of SHA256
pub const PW_SIZE_SHA256: usize = 43;

/// PWD part length of the password string of SHA512
pub const PW_SIZE_SHA512: usize = 86;

/// Maximum length of a salt
#[cfg(feature = "simple")]
pub const SALT_MAX_LEN: usize = 16;

/// Inverse encoding map for SHA512.
#[rustfmt::skip]
pub const MAP_SHA512: [u8; 64] = [
    42, 21, 0,
    1, 43, 22,
    23, 2, 44,
    45, 24, 3,
    4, 46, 25,
    26, 5, 47,
    48, 27, 6,
    7, 49, 28,
    29, 8, 50,
    51, 30, 9,
    10, 52, 31,
    32, 11, 53,
    54, 33, 12,
    13, 55, 34,
    35, 14, 56,
    57, 36, 15,
    16, 58, 37,
    38, 17, 59,
    60, 39, 18,
    19, 61, 40,
    41, 20, 62,
    63,
];

/// Inverse encoding map for SHA256.
#[rustfmt::skip]
pub const MAP_SHA256: [u8; 32] = [
    20, 10, 0,
    11, 1, 21,
    2, 22, 12,
    23, 13, 3,
    14, 4, 24,
    5, 25, 15,
    26, 16, 6,
    17, 7, 27,
    8, 28, 18,
    29, 19, 9,
    30, 31,
];
