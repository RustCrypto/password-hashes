# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.5.0 (2026-11-05)
### Added
- `PasswordVerifier<str>` impls ([#779])
- Impls for `kdf::{Kdf, Pbkdf}` ([#823])

### Changed
- Transitively enable `password-hash/alloc` if `alloc` feature is enabled ([#422])
- Upgrade to the 2024 edition and bump MSRV to 1.85 ([#563])
- Switch from `std::error::Error` to `core::error::Error` ([#767])
- Rename `simple` features to `password-hash` ([#776])
- Bump `rand_core` to v0.10; `getrandom` to v0.4 ([#836])
- Bump `password-hash` dependency to v0.6 ([#848])
- Bump `digest` dependency to v0.11 ([#849])
- Bump `sha1`, `sha2`, and `streebog` to v0.11 ([#872])
- Bump `crypto-bigint` dependency to v0.7 ([#890])

### Removed
- `std` feature (#768)

[#422]: https://github.com/RustCrypto/password-hashes/pull/422
[#563]: https://github.com/RustCrypto/password-hashes/pull/563
[#767]: https://github.com/RustCrypto/password-hashes/pull/767
[#779]: https://github.com/RustCrypto/password-hashes/pull/779
[#823]: https://github.com/RustCrypto/password-hashes/pull/823
[#836]: https://github.com/RustCrypto/password-hashes/pull/836
[#848]: https://github.com/RustCrypto/password-hashes/pull/848
[#849]: https://github.com/RustCrypto/password-hashes/pull/849
[#872]: https://github.com/RustCrypto/password-hashes/pull/872
[#890]: https://github.com/RustCrypto/password-hashes/pull/890

## 0.4.0 (2023-03-04)
### Changed
- Bump `crypto-bigint` to v0.5; MSRV 1.65 ([#381])
- Bump `password-hash` to v0.5 ([#383])

[#381]: https://github.com/RustCrypto/password-hashes/pull/381
[#383]: https://github.com/RustCrypto/password-hashes/pull/383

## 0.3.0 (2022-06-27)
### Added
- `Balloon::hash_into` ([#313])

### Changed
- Make `Error` enum non-exhaustive ([#313])

[#313]: https://github.com/RustCrypto/password-hashes/pull/313

## 0.2.1 (2022-06-16)
### Added
- `zeroize` feature ([#312])

[#312]: https://github.com/RustCrypto/password-hashes/pull/312

## 0.2.0 (2022-03-18)
### Changed
- Bump `password-hash` dependency to v0.4; MSRV 1.57 ([#283])
- 2021 edition upgrade ([#284])

[#283]: https://github.com/RustCrypto/password-hashes/pull/283
[#284]: https://github.com/RustCrypto/password-hashes/pull/284

## 0.1.1 (2022-02-17)
### Fixed
- Minimal versions build ([#273])

[#273]: https://github.com/RustCrypto/password-hashes/pull/273

## 0.1.0 (2022-01-22)
- Initial release
