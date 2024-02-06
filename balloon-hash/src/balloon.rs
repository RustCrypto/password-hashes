use crate::error::{Error, Result};
use crate::Params;
use core::mem;
use crypto_bigint::{ArrayDecoding, ArrayEncoding, NonZero};
use digest::array::Array;
use digest::{Digest, FixedOutputReset};

pub fn balloon<D: Digest + FixedOutputReset>(
    pwd: &[u8],
    salt: &[u8],
    secret: Option<&[u8]>,
    params: Params,
    memory_blocks: &mut [Array<u8, D::OutputSize>],
) -> Result<Array<u8, D::OutputSize>>
where
    Array<u8, D::OutputSize>: ArrayDecoding,
{
    if params.p_cost.get() == 1 {
        hash_internal::<D>(pwd, salt, secret, params, memory_blocks, None)
    } else {
        Err(Error::ThreadsTooMany)
    }
}

pub fn balloon_m<D: Digest + FixedOutputReset>(
    pwd: &[u8],
    salt: &[u8],
    secret: Option<&[u8]>,
    params: Params,
    memory_blocks: &mut [Array<u8, D::OutputSize>],
    output: &mut Array<u8, D::OutputSize>,
) -> Result<()>
where
    Array<u8, D::OutputSize>: ArrayDecoding,
{
    #[cfg(not(feature = "parallel"))]
    let output_xor = {
        let mut output = Array::<_, D::OutputSize>::default();

        for thread in 1..=u64::from(params.p_cost.get()) {
            let hash = hash_internal::<D>(pwd, salt, secret, params, memory_blocks, Some(thread))?;
            output = output.into_iter().zip(hash).map(|(a, b)| a ^ b).collect();
        }

        output
    };

    #[cfg(feature = "parallel")]
    let output_xor = {
        use rayon::iter::{ParallelBridge, ParallelIterator};

        if memory_blocks.len() < (params.s_cost.get() * params.p_cost.get()) as usize {
            return Err(Error::MemoryTooLittle);
        }

        // Shortcut if p_cost is one.
        if params.p_cost.get() == 1 {
            hash_internal::<D>(pwd, salt, secret, params, memory_blocks, Some(1))
        } else {
            (1..=u64::from(params.p_cost.get()))
                .zip(memory_blocks.chunks_exact_mut(params.s_cost.get() as usize))
                .par_bridge()
                .map_with((params, secret), |(params, secret), (thread, memory)| {
                    hash_internal::<D>(pwd, salt, *secret, *params, memory, Some(thread))
                })
                .try_reduce(Array::default, |a, b| {
                    Ok(a.into_iter().zip(b).map(|(a, b)| a ^ b).collect())
                })
        }?
    };

    let mut digest = D::new();
    Digest::update(&mut digest, pwd);
    Digest::update(&mut digest, salt);

    if let Some(secret) = secret {
        Digest::update(&mut digest, secret);
    }

    Digest::update(&mut digest, output_xor);
    Digest::finalize_into(digest, output);

    Ok(())
}

fn hash_internal<D: Digest + FixedOutputReset>(
    pwd: &[u8],
    salt: &[u8],
    secret: Option<&[u8]>,
    params: Params,
    memory_blocks: &mut [Array<u8, D::OutputSize>],
    thread_id: Option<u64>,
) -> Result<Array<u8, D::OutputSize>>
where
    Array<u8, D::OutputSize>: ArrayDecoding,
{
    // we will use `s_cost` to index arrays regularly
    let s_cost = params.s_cost.get() as usize;
    let s_cost_bigint = {
        let mut s_cost = Array::<u8, D::OutputSize>::default();
        s_cost[..mem::size_of::<u32>()].copy_from_slice(&params.s_cost.get().to_le_bytes());
        NonZero::new(s_cost.into_uint_le()).unwrap()
    };

    let mut digest = D::new();

    // This is a direct translation of the `Balloon` from <https://eprint.iacr.org/2016/027.pdf> chapter 3.1.
    // int delta = 3 // Number of dependencies per block
    const DELTA: u64 = 3;
    // int cnt = 0 // A counter (used in security proof)
    let mut cnt: u64 = 0;
    // block_t buf[s_cost]): // The main buffer
    let buf = memory_blocks
        .get_mut(..s_cost)
        .ok_or(Error::MemoryTooLittle)?;

    // Step 1. Expand input into buffer.
    // buf[0] = hash(cnt++, passwd, salt)
    Digest::update(&mut digest, cnt.to_le_bytes());
    cnt += 1;
    Digest::update(&mut digest, pwd);
    Digest::update(&mut digest, salt);

    if let Some(secret) = secret {
        Digest::update(&mut digest, secret);
    }

    if let Some(thread_id) = thread_id {
        Digest::update(&mut digest, thread_id.to_le_bytes());
    }

    buf[0] = digest.finalize_reset();

    // for m from 1 to s_cost-1:
    for m in 1..s_cost {
        // buf[m] = hash(cnt++, buf[m-1])
        Digest::update(&mut digest, cnt.to_le_bytes());
        cnt += 1;
        Digest::update(&mut digest, &buf[m - 1]);
        buf[m] = digest.finalize_reset();
    }

    // Step 2. Mix buffer contents.
    // for t from 0 to t_cost-1:
    for t in 0..u64::from(params.t_cost.get()) {
        // for m from 0 to s_cost-1:
        for m in 0..s_cost {
            // Step 2a. Hash last and current blocks.
            // block_t prev = buf[(m-1) mod s_cost]
            let prev = if m == 0 {
                buf.last().unwrap()
            } else {
                &buf[m - 1]
            };

            // buf[m] = hash(cnt++, prev, buf[m])
            Digest::update(&mut digest, cnt.to_le_bytes());
            cnt += 1;
            Digest::update(&mut digest, prev);
            Digest::update(&mut digest, &buf[m]);
            buf[m] = digest.finalize_reset();

            // Step 2b. Hash in pseudorandomly chosen blocks.
            // for i from 0 to delta-1:
            for i in 0..DELTA {
                // block_t idx_block = ints_to_block(t, m, i)
                Digest::update(&mut digest, t.to_le_bytes());
                Digest::update(&mut digest, (m as u64).to_le_bytes());
                Digest::update(&mut digest, i.to_le_bytes());
                let idx_block = digest.finalize_reset();

                // int other = to_int(hash(cnt++, salt, idx_block)) mod s_cost
                Digest::update(&mut digest, cnt.to_le_bytes());
                cnt += 1;
                Digest::update(&mut digest, salt);

                if let Some(secret) = secret {
                    Digest::update(&mut digest, secret);
                }

                if let Some(thread_id) = thread_id {
                    Digest::update(&mut digest, thread_id.to_le_bytes());
                }

                Digest::update(&mut digest, idx_block);
                let other = digest.finalize_reset().into_uint_le() % s_cost_bigint.clone();
                let other = usize::from_le_bytes(
                    other.to_le_byte_array()[..mem::size_of::<usize>()]
                        .try_into()
                        .unwrap(),
                );

                // buf[m] = hash(cnt++, buf[m], buf[other])
                Digest::update(&mut digest, cnt.to_le_bytes());
                cnt += 1;
                Digest::update(&mut digest, &buf[m]);
                Digest::update(&mut digest, &buf[other]);
                buf[m] = digest.finalize_reset();
            }
        }
    }

    // Step 3. Extract output from buffer.
    // return buf[s_cost-1]
    Ok(buf.last().unwrap().clone())
}
