/// Permute Salsa20 block to diagonal order
pub(crate) const PIVOT_ABCD: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

/// Inverse of PIVOT_ABCD
pub(crate) const INVERSE_PIVOT_ABCD: [usize; 16] = const {
    let mut index = [0; 16];
    let mut i = 0;
    while i < 16 {
        let mut inverse = 0;
        while inverse < 16 {
            if PIVOT_ABCD[inverse] == i {
                index[i] = inverse;
                break;
            }
            inverse += 1;
        }
        i += 1;
    }
    index
};
