/// Block size for MD5
pub const BLOCK_SIZE: usize = 16;

/// PWD part length of the password string
pub const PW_SIZE_MD5: usize = 22;

/// Maximum length of a salt
pub const SALT_MAX_LEN: usize = 8;

/// Encoding table.
#[cfg(feature = "simple")]
pub static TAB: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Inverse encoding map for MD5.
pub const MAP_MD5: [u8; BLOCK_SIZE] = [12, 6, 0, 13, 7, 1, 14, 8, 2, 15, 9, 3, 5, 10, 4, 11];
