#![cfg_attr(not(feature = "std"), no_std)]
extern crate crypto_mac;
extern crate generic_array;
extern crate byte_tools;

#[cfg(feature="parallel")]
extern crate rayon;
#[cfg(feature="parallel")]
use rayon::prelude::*;

use crypto_mac::Mac;
use generic_array::typenum::Unsigned;
use byte_tools::write_u32_be;

#[inline(always)]
fn xor(res: &mut [u8], salt: &[u8]) {
    assert!(salt.len() >= salt.len());
    for i in 0..res.len() {
        res[i] ^= salt[i];
    }
}

#[inline(always)]
fn pbkdf2_body<F>(i: usize, chunk: &mut [u8], prf: &F, salt: &[u8], c: usize)
    where F: Mac + Clone
{
    for v in chunk.iter_mut() { *v = 0; }

    let mut salt = {
        let mut prfc = prf.clone();
        prfc.input(salt);

        let mut buf = [0u8; 4];
        write_u32_be(&mut buf, (i + 1) as u32);
        prfc.input(&buf);

        let salt = prfc.result();
        xor(chunk, salt.code());
        salt
    };

    for _ in 1..c {
        let mut prfc = prf.clone();
        prfc.input(&salt.code());
        salt = prfc.result();

        xor(chunk, salt.code());
    }
}

#[cfg(feature="parallel")]
#[inline]
pub fn pbkdf2<F>(password: &[u8], salt: &[u8], c: usize, res: &mut [u8])
    where F: Mac + Clone + Sync
{
    let n = F::OutputSize::to_usize();
    let prf = F::new(password);

    res.par_chunks_mut(n).enumerate().for_each(|(i, chunk)| {
        pbkdf2_body(i, chunk, &prf, salt, c);
    });
}

#[cfg(not(feature="parallel"))]
#[inline]
pub fn pbkdf2<F>(password: &[u8], salt: &[u8], c: usize, res: &mut [u8])
    where F: Mac + Clone + Sync
{
    let n = F::OutputSize::to_usize();
    let prf = F::new(password);

    for (i, chunk) in res.chunks_mut(n).enumerate() {
        pbkdf2_body(i, chunk, &prf, salt, c);
    }
}
