//! This crate implements [bcrypt_pbkdf], a custom derivative of PBKDF2 used in
//! [OpenSSH].
//!
//! [bcrypt_pbkdf]: https://flak.tedunangst.com/post/bcrypt-pbkdf
//! [OpenSSH]: https://flak.tedunangst.com/post/new-openssh-key-format-and-bcrypt-pbkdf

#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod errors;

pub use errors::Error;

use blowfish::Blowfish;
use sha2::{
    digest::{
        crypto_common::{Key, KeyInit, KeySizeUser},
        generic_array::typenum::U32,
        FixedOutput, MacMarker, Output, OutputSizeUser, Update,
    },
    Digest, Sha512,
};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

const BHASH_WORDS: usize = 8;
const BHASH_OUTPUT_SIZE: usize = BHASH_WORDS * 4;
const BHASH_SEED: &[u8; BHASH_OUTPUT_SIZE] = b"OxychromaticBlowfishSwatDynamite";

fn bhash(sha2_pass: &Output<Sha512>, sha2_salt: &Output<Sha512>) -> Output<Bhash> {
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
            let [l, r] = blowfish.bc_encrypt([cdata[i], cdata[i + 1]]);
            cdata[i] = l;
            cdata[i + 1] = r;
        }
    }

    let mut output = Output::<Bhash>::default();
    for i in 0..BHASH_WORDS {
        output[i * 4..(i + 1) * 4].copy_from_slice(&cdata[i].to_le_bytes());
    }

    output
}

#[derive(Clone)]
struct Bhash {
    sha2_pass: Output<Sha512>,
    salt: Sha512,
}

impl MacMarker for Bhash {}

impl KeySizeUser for Bhash {
    type KeySize = <Sha512 as OutputSizeUser>::OutputSize;
}

impl KeyInit for Bhash {
    fn new(key: &Key<Self>) -> Self {
        Bhash {
            sha2_pass: *key,
            salt: Sha512::default(),
        }
    }
}

impl Update for Bhash {
    fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.salt, data);
    }
}

impl OutputSizeUser for Bhash {
    type OutputSize = U32;
}

impl FixedOutput for Bhash {
    fn finalize_into(mut self, out: &mut Output<Self>) {
        *out = bhash(&self.sha2_pass, &self.salt.finalize_reset());
    }
}

#[cfg(feature = "zeroize")]
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
#[cfg(feature = "alloc")]
pub fn bcrypt_pbkdf(
    passphrase: impl AsRef<[u8]>,
    salt: &[u8],
    rounds: u32,
    output: &mut [u8],
) -> Result<(), Error> {
    /// number of strides which will be processed on stack
    const STACK_STRIDE: usize = 8;

    // Allocate a Vec large enough to hold the output we require.
    let stride = (output.len() + BHASH_OUTPUT_SIZE - 1) / BHASH_OUTPUT_SIZE;

    let mut vec_buf;
    let mut stack_buf = [0u8; STACK_STRIDE * BHASH_OUTPUT_SIZE];
    let generated = if stride > STACK_STRIDE {
        vec_buf = alloc::vec![0u8; stride * BHASH_OUTPUT_SIZE];
        &mut vec_buf[..]
    } else {
        &mut stack_buf[..stride * BHASH_OUTPUT_SIZE]
    };

    bcrypt_pbkdf_with_memory(passphrase, salt, rounds, output, generated)
}

/// Like [`bcrypt_pbkdf`], but usable on "heapless" targets.
///
/// # Arguments
/// - `passphrase` - The passphrase to process.
/// - `salt` - The salt value to use as a byte vector.
/// - `rounds` - The number of rounds to apply.
/// - `output` - The resulting derived key is returned in this byte vector.
/// - `memory` - Buffer space used for internal computation.
///
/// # Returns
/// - `Ok(())` if everything is fine.
/// - `Err(Error::InvalidParamLen)` if `passphrase.is_empty() || salt.is_empty()`.
/// - `Err(Error::InvalidRounds)` if `rounds == 0`.
/// - `Err(Error::InvalidOutputLen)` if `output.is_empty() || output.len() > 1024`.
/// - `Err(Error::InvalidMemoryLen)` if `memory.len() < (output.len() + 32 - 1) / 32 * 32`, i.e.
///   `output.len()` rounded up to the nearest multiple of 32.
pub fn bcrypt_pbkdf_with_memory(
    passphrase: impl AsRef<[u8]>,
    salt: &[u8],
    rounds: u32,
    output: &mut [u8],
    memory: &mut [u8],
) -> Result<(), Error> {
    let stride = (output.len() + BHASH_OUTPUT_SIZE - 1) / BHASH_OUTPUT_SIZE;

    // Validate inputs in same way as OpenSSH implementation
    let passphrase = passphrase.as_ref();
    if passphrase.is_empty() || salt.is_empty() {
        return Err(errors::Error::InvalidParamLen);
    } else if rounds == 0 {
        return Err(errors::Error::InvalidRounds);
    } else if output.is_empty() || output.len() > BHASH_OUTPUT_SIZE * BHASH_OUTPUT_SIZE {
        return Err(errors::Error::InvalidOutputLen);
    } else if memory.len() < stride * BHASH_OUTPUT_SIZE {
        return Err(errors::Error::InvalidMemoryLen);
    }

    // Run the regular PBKDF2 algorithm with bhash as the PRF.
    pbkdf2::pbkdf2::<Bhash>(&Sha512::digest(passphrase), salt, rounds, memory)
        .expect("Bhash can be initialized with any key length");

    // Apply the bcrypt_pbkdf non-linear transformation on the output.
    for (i, out_byte) in output.iter_mut().enumerate() {
        let chunk_num = i % stride;
        let chunk_index = i / stride;
        *out_byte = memory[chunk_num * BHASH_OUTPUT_SIZE + chunk_index];
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::bhash;
    use hex_literal::hex;
    use sha2::digest::generic_array::GenericArray;

    #[test]
    fn test_bhash() {
        struct Test {
            hpass: [u8; 64],
            hsalt: [u8; 64],
            out: [u8; 32],
        }

        const TEST_VAL: [u8; 64] = hex!(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f"
            "303132333435363738393a3b3c3d3e3f"
        );

        let tests = [
            Test {
                hpass: [0; 64],
                hsalt: [0; 64],
                out: hex!(
                    "460286e972fa833f8b1283ad8fa919fa"
                    "29bde20e23329e774d8422bac0a7926c"
                ),
            },
            Test {
                hpass: TEST_VAL,
                hsalt: [0; 64],
                out: hex!(
                    "b0b229dbc6badef0e1da2527474a8b28"
                    "888f8b061476fe80c32256e1142dd00d"
                ),
            },
            Test {
                hpass: [0; 64],
                hsalt: TEST_VAL,
                out: hex!(
                    "b62b4e367d3157f5c31e4d2cbafb2931"
                    "494d9d3bdd171d55cf799fa4416042e2"
                ),
            },
            Test {
                hpass: TEST_VAL,
                hsalt: TEST_VAL,
                out: hex!(
                    "c6a95fe6413115fb57e99f757498e85d"
                    "a3c6e1df0c3c93aa975c548a344326f8"
                ),
            },
        ];

        for t in tests.iter() {
            let hpass = GenericArray::from_slice(&t.hpass);
            let hsalt = GenericArray::from_slice(&t.hsalt);
            let out = bhash(hpass, hsalt);
            assert_eq!(out[..], t.out[..]);
        }
    }
}
