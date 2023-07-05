use argon2::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

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

fn bench_vary_m(c: &mut Criterion) {
    let t_cost = 4;
    let p_cost = 4;
    for m_cost in [2 * 1024, 16 * 1024, 64 * 1024, 256 * 1024] {
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

fn bench_vary_t(c: &mut Criterion) {
    let m_cost = 32 * 1024;
    let p_cost = 4;
    for t_cost in [2, 8, 16, 24] {
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

fn bench_vary_p(c: &mut Criterion) {
    let m_cost = 32 * 1024;
    let t_cost = 4;
    for p_cost in [2, 8, 16, 64] {
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
    benches,
    bench_default_params,
    bench_vary_m,
    bench_vary_t,
    bench_vary_p,
);
criterion_main!(benches);
