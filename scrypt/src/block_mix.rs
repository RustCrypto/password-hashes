cfg_if::cfg_if! {
    if #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))] {
        mod pivot;
        mod simd128;
        pub(crate) use simd128::{scrypt_block_mix, shuffle_in, shuffle_out};
    } else if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sse2"))] {
        mod pivot;
        mod sse2;
        pub(crate) use sse2::{scrypt_block_mix, shuffle_in, shuffle_out};
    } else {
        mod soft;
        pub(crate) use soft::scrypt_block_mix;

        pub(crate) fn shuffle_in(_input: &mut [u8]) {}
        pub(crate) fn shuffle_out(_input: &mut [u8]) {}
    }
}

#[cfg(test)]
#[path = "block_mix/soft.rs"]
mod soft_test;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrypt_block_mix_abcd_against_soft() {
        let mut input: [u8; 128] = core::array::from_fn(|i| i as u8);
        for _round in 0..10 {
            let mut output = [0u8; 128];

            let mut expected0 = [0u8; 128];
            let mut expected1 = [0u8; 128]; // check shuffle_out is a correct inverse of shuffle_in
            soft_test::scrypt_block_mix(&input, &mut expected0);
            shuffle_in(&mut input);
            scrypt_block_mix(&input, &mut output);
            shuffle_out(&mut input);
            soft_test::scrypt_block_mix(&input, &mut expected1);
            shuffle_out(&mut output);
            assert_eq!(
                expected0, expected1,
                "expected0 != expected1, shuffle_out is not a correct inverse of shuffle_in?"
            );
            assert_eq!(
                output, expected0,
                "output != expected0, scrypt_block_mix is not correct?"
            );

            input
                .iter_mut()
                .zip(output.iter())
                .for_each(|(a, b)| *a = a.wrapping_add(*b));
        }
    }
}
