/// Block size for SHA512
pub const BLOCK_SIZE: usize = 64;

/// PWD part length of the password string of sha-512
pub const PW_SIZE_SHA512: usize = 86;

/// Maximum length of a salt
#[cfg(feature = "simple")]
pub const SALT_MAX_LEN: usize = 16;

/// Encoding table.
#[cfg(feature = "simple")]
pub static TAB: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Inverse encoding map for SHA512.
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
