use std::collections::HashSet;

use argon2::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pprof::criterion::{Output, PProfProfiler};

const BENCH_PASSWORD: &[u8] = b"hunter2";
const BENCH_SALT: &[u8] = b"pepper42";

fn bench_default_params(c: &mut Criterion) {
    for algorithm in [Algorithm::Argon2i, Algorithm::Argon2d, Algorithm::Argon2id] {
        for version in [Version::V0x10, Version::V0x13] {
            let test_name = format!("{algorithm} {version:?}");
            c.bench_function(&test_name, |b| {
                let mut out = [0u8; 32];
                let argon2 = Argon2::new(algorithm, version, Params::default());
                b.iter(|| {
                    argon2
                        .hash_password_into(
                            black_box(BENCH_PASSWORD),
                            black_box(BENCH_SALT),
                            &mut out,
                        )
                        .unwrap()
                })
            });
        }
    }
}

fn bench_vary_params(c: &mut Criterion) {
    let mut tests = HashSet::new();
    // Vary `m_cost`.
    for m_cost in [2 * 1024, 16 * 1024, 32 * 1024, 64 * 1024, 256 * 1024] {
        tests.insert((m_cost, 4, 4));
    }
    // Vary `t_cost`.
    for t_cost in [1, 2, 4, 8, 16] {
        tests.insert((32 * 1024, t_cost, 4));
    }
    // Vary `p_cost`.
    for p_cost in [1, 2, 4, 8, 16] {
        for m_mib in [256 * 1024, 1024 * 1024] {
            tests.insert((m_mib, 1, p_cost));
        }
        for t_cost in [1, 2, 4] {
            tests.insert((32 * 1024, t_cost, p_cost));
        }
    }
    for (m_cost, t_cost, p_cost) in tests {
        let test_name = format!("argon2id V0x13 m={m_cost} t={t_cost} p={p_cost}");
        c.bench_function(&test_name, |b| {
            let mut out = [0u8; 32];
            let params = Params::new(m_cost, t_cost, p_cost, Some(32)).unwrap();
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            b.iter(|| {
                argon2
                    .hash_password_into(black_box(BENCH_PASSWORD), black_box(BENCH_SALT), &mut out)
                    .unwrap()
            })
        });
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(300, Output::Flamegraph(None)));
    targets =
    bench_default_params,
    bench_vary_params,
);
criterion_main!(benches);
