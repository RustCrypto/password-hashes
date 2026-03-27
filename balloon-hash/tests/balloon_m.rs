use balloon_hash::{Algorithm, Balloon, Params};
use digest::array::Array;

#[path = "../data/balloon_m.rs"]
mod test_vectors;
use test_vectors::BALLOON_M_TEST_VECTORS;

#[test]
fn test_vectors() {
    for test_vector in BALLOON_M_TEST_VECTORS {
        let balloon = Balloon::<sha2::Sha256>::new(
            Algorithm::BalloonM,
            Params::new(test_vector.s_cost, test_vector.t_cost, test_vector.p_cost).unwrap(),
            None,
        );

        #[cfg(not(feature = "parallel"))]
        let mut memory = vec![Array::default(); balloon.params.s_cost.get() as usize];
        #[cfg(feature = "parallel")]
        let mut memory = vec![
            Array::default();
            (balloon.params.s_cost.get() * balloon.params.p_cost.get()) as usize
        ];

        assert_eq!(
            balloon
                .hash_password_with_memory(test_vector.password, test_vector.salt, &mut memory)
                .unwrap()
                .as_slice(),
            test_vector.output,
        );
    }
}
