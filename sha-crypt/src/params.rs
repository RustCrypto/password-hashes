pub const ROUNDS_DEFAULT: usize = 5_000;
pub const ROUNDS_MIN: usize = 1_000;
pub const ROUNDS_MAX: usize = 999_999_999;

#[derive(Debug)]
pub struct Sha512Params {
    pub rounds: usize,
}
