# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 2.0.0 (2026-11-04)
### Changed
- Upgrade to the Rust 2024 edition and bump MSRV to 1.85 ([#563])
- Switch from `std::error::Error` to `core::error::Error` ([#767])
- Upgrade `rand_core` to v0.10 ([#836])
- Upgrade `password-hash` dependency to v0.6 ([#848])
- Upgrade `pbkdf2` dependency to v0.13 ([#885])
- Upgrade `scrypt` dependency to v0.12 ([#897])
- Upgrade `getrandom` dependency to v0.4; `argon2` to v0.6 ([#944])

### Removed
- `std` feature ([#945])
- `wasm_js` feature ([#946])

[#563]: https://github.com/RustCrypto/password-hashes/pull/563
[#767]: https://github.com/RustCrypto/password-hashes/pull/767
[#836]: https://github.com/RustCrypto/password-hashes/pull/836
[#848]: https://github.com/RustCrypto/password-hashes/pull/848
[#885]: https://github.com/RustCrypto/password-hashes/pull/885
[#897]: https://github.com/RustCrypto/password-hashes/pull/897
[#944]: https://github.com/RustCrypto/password-hashes/pull/944
[#945]: https://github.com/RustCrypto/password-hashes/pull/945
[#946]: https://github.com/RustCrypto/password-hashes/pull/946

## 1.0.0 (2023-09-03)
No changes from v0.3.0.

## 0.3.0 (2023-06-24)
### Added
- Derive `Eq`/`PartialEq` on `*Error` ([#433])

### Changed
- Rename `Error` (back) to `VerifyError` ([#432])

[#432]: https://github.com/RustCrypto/password-hashes/pull/432
[#433]: https://github.com/RustCrypto/password-hashes/pull/433

## 0.2.0 (2023-06-24)
### Added
- `is_hash_obsolete` ([#428])

### Changed
- Replace `VerifyError` with `Error` enum ([#429])

[#428]: https://github.com/RustCrypto/password-hashes/pull/428
[#429]: https://github.com/RustCrypto/password-hashes/pull/429

## 0.1.1 (2023-06-01)
### Changed
- Improve documentation ([#419])

[#419]: https://github.com/RustCrypto/password-hashes/pull/419

## 0.1.0 (2023-03-14)
- Initial release
