extern crate bcrypt_pbkdf;

use bcrypt_pbkdf::bcrypt_pbkdf_with_memory;
#[path = "../data/test_vectors.rs"]
mod test_vectors;
use test_vectors::TEST_VECTORS;

#[test]
fn test_openbsd_vectors() {
    for t in TEST_VECTORS.iter() {
        let mut out = vec![0; t.out.len()];
        let len = t.out.len().div_ceil(32) * 32;
        let mut memory = vec![0; len];
        bcrypt_pbkdf_with_memory(t.password, &t.salt[..], t.rounds, &mut out, &mut memory).unwrap();
        assert_eq!(out, t.out);
    }
}
