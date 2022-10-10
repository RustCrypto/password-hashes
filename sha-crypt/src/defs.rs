/// Block size for SHA512
pub const BLOCK_SIZE_SHA512: usize = 64;

/// Block size for SHA256
pub const BLOCK_SIZE_SHA256: usize = 32;

/// Maximum length of a salt
#[cfg(feature = "simple")]
pub const SALT_MAX_LEN: usize = 16;

/// Encoding table.
pub static TAB: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Inverse encoding map for SHA512.
pub const MAP_SHA512: [(u8, u8, u8, u8); 22] = [
    (42, 21, 0, 4),
    (1, 43, 22, 4),
    (23, 2, 44, 4),
    (45, 24, 3, 4),
    (4, 46, 25, 4),
    (26, 5, 47, 4),
    (48, 27, 6, 4),
    (7, 49, 28, 4),
    (29, 8, 50, 4),
    (51, 30, 9, 4),
    (10, 52, 31, 4),
    (32, 11, 53, 4),
    (54, 33, 12, 4),
    (13, 55, 34, 4),
    (35, 14, 56, 4),
    (57, 36, 15, 4),
    (16, 58, 37, 4),
    (38, 17, 59, 4),
    (60, 39, 18, 4),
    (19, 61, 40, 4),
    (41, 20, 62, 4),
    (63, 0, 0, 2),
];

/// Inverse encoding map for SHA256.
pub const MAP_SHA256: [(u8, u8, u8, u8); 11] = [
    (20, 10, 0, 4),
    (11, 1, 21, 4),
    (2, 22, 12, 4),
    (23, 13, 3, 4),
    (14, 4, 24, 4),
    (5, 25, 15, 4),
    (26, 16, 6, 4),
    (17, 7, 27, 4),
    (8, 28, 18, 4),
    (29, 19, 9, 4),
    (30, 31, 0, 3),
];
