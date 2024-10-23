use libfuzzer_sys::arbitrary::{Arbitrary, Result, Unstructured};

#[derive(Debug)]
pub struct ScryptRandParams(pub scrypt::Params);

impl<'a> Arbitrary<'a> for ScryptRandParams {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let log_n = u.int_in_range(0..=15)?;
        let r = u.int_in_range(1..=32)?;
        let p = u.int_in_range(1..=16)?;
        let len = u.int_in_range(10..=64)?;

        let params = scrypt::Params::new(log_n, r, p, len).unwrap();
        Ok(Self(params))
    }
}
