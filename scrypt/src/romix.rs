/// Execute the ROMix operation in-place.
/// b - the data to operate on
/// v - a temporary variable to store the vector V
/// t - a temporary variable to store the result of the xor
/// n - the scrypt parameter N
#[allow(clippy::many_single_char_names)]
pub(crate) fn scrypt_ro_mix(b: &mut [u8], v: &mut [u8], t: &mut [u8], n: usize) {
    fn integerify(x: &[u8], n: usize) -> usize {
        // n is a power of 2, so n - 1 gives us a bitmask that we can use to perform a calculation
        // mod n using a simple bitwise and.
        let mask = n - 1;
        // This cast is safe since we're going to get the value mod n (which is a power of 2), so we
        // don't have to care about truncating any of the high bits off
        //let result = (LittleEndian::read_u32(&x[x.len() - 64..x.len() - 60]) as usize) & mask;
        let t = u32::from_le_bytes(x[x.len() - 64..x.len() - 60].try_into().unwrap());
        (t as usize) & mask
    }

    let len = b.len();

    crate::block_mix::shuffle_in(b);

    for chunk in v.chunks_mut(len) {
        chunk.copy_from_slice(b);
        crate::block_mix::scrypt_block_mix(chunk, b);
    }

    for _ in 0..n {
        let j = integerify(b, n);
        xor(b, &v[j * len..(j + 1) * len], t);

        crate::block_mix::scrypt_block_mix(t, b);
    }

    crate::block_mix::shuffle_out(b);
}

fn xor(x: &[u8], y: &[u8], output: &mut [u8]) {
    for ((out, &x_i), &y_i) in output.iter_mut().zip(x.iter()).zip(y.iter()) {
        *out = x_i ^ y_i;
    }
}
