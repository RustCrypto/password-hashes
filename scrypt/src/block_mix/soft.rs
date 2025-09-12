/// Execute the BlockMix operation
/// input - the input vector. The length must be a multiple of 128.
/// output - the output vector. Must be the same length as input.
pub(crate) fn scrypt_block_mix(input: &[u8], output: &mut [u8]) {
    use salsa20::{
        SalsaCore,
        cipher::{StreamCipherCore, typenum::U4},
    };

    type Salsa20_8 = SalsaCore<U4>;

    let mut x = [0u8; 64];
    x.copy_from_slice(&input[input.len() - 64..]);

    let mut t = [0u8; 64];

    for (i, chunk) in input.chunks(64).enumerate() {
        xor(&x, chunk, &mut t);

        let mut t2 = [0u32; 16];

        for (c, b) in t.chunks_exact(4).zip(t2.iter_mut()) {
            *b = u32::from_le_bytes(c.try_into().unwrap());
        }

        Salsa20_8::from_raw_state(t2).write_keystream_block((&mut x).into());

        let pos = if i % 2 == 0 {
            (i / 2) * 64
        } else {
            (i / 2) * 64 + input.len() / 2
        };

        output[pos..pos + 64].copy_from_slice(&x);
    }
}

fn xor(x: &[u8], y: &[u8], output: &mut [u8]) {
    for ((out, &x_i), &y_i) in output.iter_mut().zip(x.iter()).zip(y.iter()) {
        *out = x_i ^ y_i;
    }
}
