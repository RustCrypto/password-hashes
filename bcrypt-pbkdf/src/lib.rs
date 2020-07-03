//! This crate implements [bcrypt_pbkdf], a custom derivative of PBKDF2 used in
//! [OpenSSH].
//!
//! [bcrypt_pbkdf]: https://flak.tedunangst.com/post/bcrypt-pbkdf
//! [OpenSSH]: https://flak.tedunangst.com/post/new-openssh-key-format-and-bcrypt-pbkdf
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]

use blowfish::Blowfish;
use core::convert::TryInto;
use crypto_mac::{
    generic_array::{typenum::U32, GenericArray},
    Mac, NewMac, Output,
};
use pbkdf2::pbkdf2;
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

mod errors;

pub use errors::Error;

const BHASH_WORDS: usize = 8;
const BHASH_OUTPUT_SIZE: usize = BHASH_WORDS * 4;
const BHASH_SEED: &[u8; BHASH_OUTPUT_SIZE] = b"OxychromaticBlowfishSwatDynamite";

fn bhash(sha2_pass: &[u8], sha2_salt: &[u8]) -> [u8; BHASH_OUTPUT_SIZE] {
    assert_eq!(sha2_pass.len(), <Sha512 as Digest>::output_size());
    assert_eq!(sha2_salt.len(), <Sha512 as Digest>::output_size());

    let mut blowfish = Blowfish::bc_init_state();

    blowfish.salted_expand_key(sha2_salt, sha2_pass);
    for _ in 0..64 {
        blowfish.bc_expand_key(sha2_salt);
        blowfish.bc_expand_key(sha2_pass);
    }

    let mut cdata = [0u32; BHASH_WORDS];
    for i in 0..BHASH_WORDS {
        cdata[i] = u32::from_be_bytes(BHASH_SEED[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    for _ in 0..64 {
        for i in (0..BHASH_WORDS).step_by(2) {
            let (l, r) = blowfish.bc_encrypt(cdata[i], cdata[i + 1]);
            cdata[i] = l;
            cdata[i + 1] = r;
        }
    }

    let mut output = [0u8; BHASH_OUTPUT_SIZE];
    for i in 0..BHASH_WORDS {
        output[i * 4..(i + 1) * 4].copy_from_slice(&cdata[i].to_le_bytes());
    }

    cdata.zeroize();

    output
}

#[derive(Clone)]
struct Bhash {
    sha2_pass: GenericArray<u8, <Sha512 as Digest>::OutputSize>,
    salt: Sha512,
}

impl NewMac for Bhash {
    type KeySize = <Sha512 as Digest>::OutputSize;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        Bhash {
            sha2_pass: *key,
            salt: Sha512::default(),
        }
    }
}

impl Mac for Bhash {
    type OutputSize = U32;

    fn update(&mut self, data: &[u8]) {
        self.salt.update(data);
    }

    fn reset(&mut self) {
        self.salt.reset();
    }

    fn finalize(mut self) -> Output<Self> {
        let mut output = bhash(&self.sha2_pass, &self.salt.finalize_reset());
        let res = Output::new(GenericArray::clone_from_slice(&output[..]));
        output.zeroize();
        res
    }
}

impl Drop for Bhash {
    fn drop(&mut self) {
        self.sha2_pass.zeroize();
    }
}

/// The bcrypt_pbkdf function.
///
/// # Arguments
/// - `passphrase` - The passphrase to process.
/// - `salt` - The salt value to use as a byte vector.
/// - `rounds` - The number of rounds to apply.
/// - `output` - The resulting derived key is returned in this byte vector.
///
/// # Returns
/// - `Ok(())` if everything is fine.
/// - `Err(Error::InvalidParamLen)` if `passphrase.is_empty() || salt.is_empty()`.
/// - `Err(Error::InvalidRounds)` if `rounds == 0`.
/// - `Err(Error::InvalidOutputLen)` if `output.is_empty() || output.len() > 1024`.
pub fn bcrypt_pbkdf(
    passphrase: &str,
    salt: &[u8],
    rounds: u32,
    output: &mut [u8],
) -> Result<(), Error> {
    // Validate inputs in same way as OpenSSH implementation
    if passphrase.is_empty() || salt.is_empty() {
        return Err(errors::Error::InvalidParamLen);
    } else if rounds == 0 {
        return Err(errors::Error::InvalidRounds);
    } else if output.is_empty() || output.len() > BHASH_OUTPUT_SIZE * BHASH_OUTPUT_SIZE {
        return Err(errors::Error::InvalidOutputLen);
    }

    // Allocate a Vec large enough to hold the output we require.
    let stride = (output.len() + BHASH_OUTPUT_SIZE - 1) / BHASH_OUTPUT_SIZE;
    let mut generated = vec![0; stride * BHASH_OUTPUT_SIZE];

    // Run the regular PBKDF2 algorithm with bhash as the MAC.
    pbkdf2::<Bhash>(
        &Sha512::digest(passphrase.as_bytes()),
        salt,
        rounds,
        &mut generated,
    );

    // Apply the bcrypt_pbkdf non-linear transformation on the output.
    for (i, out_byte) in output.iter_mut().enumerate() {
        let chunk_num = i % stride;
        let chunk_index = i / stride;
        *out_byte = generated[chunk_num * BHASH_OUTPUT_SIZE + chunk_index];
    }

    generated.zeroize();

    Ok(())
}

#[cfg(test)]
mod test {
    use super::bhash;

    #[test]
    fn test_bhash() {
        struct Test {
            hpass: [u8; 64],
            hsalt: [u8; 64],
            out: [u8; 32],
        }

        let tests = vec![
            Test {
                hpass: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                hsalt: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                out: [
                    0x46, 0x02, 0x86, 0xe9, 0x72, 0xfa, 0x83, 0x3f, 0x8b, 0x12, 0x83, 0xad, 0x8f,
                    0xa9, 0x19, 0xfa, 0x29, 0xbd, 0xe2, 0x0e, 0x23, 0x32, 0x9e, 0x77, 0x4d, 0x84,
                    0x22, 0xba, 0xc0, 0xa7, 0x92, 0x6c,
                ],
            },
            Test {
                hpass: [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                    0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
                    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                ],
                hsalt: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                out: [
                    0xb0, 0xb2, 0x29, 0xdb, 0xc6, 0xba, 0xde, 0xf0, 0xe1, 0xda, 0x25, 0x27, 0x47,
                    0x4a, 0x8b, 0x28, 0x88, 0x8f, 0x8b, 0x06, 0x14, 0x76, 0xfe, 0x80, 0xc3, 0x22,
                    0x56, 0xe1, 0x14, 0x2d, 0xd0, 0x0d,
                ],
            },
            Test {
                hpass: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                hsalt: [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                    0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
                    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                ],
                out: [
                    0xb6, 0x2b, 0x4e, 0x36, 0x7d, 0x31, 0x57, 0xf5, 0xc3, 0x1e, 0x4d, 0x2c, 0xba,
                    0xfb, 0x29, 0x31, 0x49, 0x4d, 0x9d, 0x3b, 0xdd, 0x17, 0x1d, 0x55, 0xcf, 0x79,
                    0x9f, 0xa4, 0x41, 0x60, 0x42, 0xe2,
                ],
            },
            Test {
                hpass: [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                    0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
                    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                ],
                hsalt: [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                    0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
                    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                ],
                out: [
                    0xc6, 0xa9, 0x5f, 0xe6, 0x41, 0x31, 0x15, 0xfb, 0x57, 0xe9, 0x9f, 0x75, 0x74,
                    0x98, 0xe8, 0x5d, 0xa3, 0xc6, 0xe1, 0xdf, 0x0c, 0x3c, 0x93, 0xaa, 0x97, 0x5c,
                    0x54, 0x8a, 0x34, 0x43, 0x26, 0xf8,
                ],
            },
        ];

        for t in tests.iter() {
            let out = bhash(&t.hpass, &t.hsalt);
            assert_eq!(out, t.out);
        }
    }
}
