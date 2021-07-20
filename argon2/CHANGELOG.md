# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.2 (2021-07-20)
### Changed
- Pin `zeroize` dependency to v1.3 ([#190])

[#190]: https://github.com/RustCrypto/password-hashes/pull/190

## 0.2.1 (2021-05-28)
### Changed
- `Params` always available; no longer feature-gated on `password-hash` ([#182])

### Fixed
- Configured params are used with `hash_password_simple` ([#182])

[#182]: https://github.com/RustCrypto/password-hashes/pull/182

## 0.2.0 (2021-04-29)
### Changed
- Forbid unsafe code outside parallel implementation ([#157])
- Bump `password-hash` crate dependency to v0.2 ([#164])

### Removed
- `argon2::BLOCK_SIZE` constant ([#161])

[#157]: https://github.com/RustCrypto/password-hashes/pull/157
[#161]: https://github.com/RustCrypto/password-hashes/pull/161
[#164]: https://github.com/RustCrypto/password-hashes/pull/164

## 0.1.5 (2021-04-18)
### Added
- Parallel lane processing using `rayon` ([#149])

[#149]: https://github.com/RustCrypto/password-hashes/pull/149

## 0.1.4 (2021-02-28)
### Added
- `std` feature ([#141])

[#141]: https://github.com/RustCrypto/password-hashes/pull/141

## 0.1.3 (2021-02-12)
### Fixed
- Salt-length related panic ([#135])

[#135]: https://github.com/RustCrypto/password-hashes/pull/135

## 0.1.2 (2021-02-07)
### Fixed
- rustdoc typo ([#128])

[#128]: https://github.com/RustCrypto/password-hashes/pull/128

## 0.1.1 (2021-02-07)
### Added
- `rand` feature; enabled-by-default ([#126])

[#126]: https://github.com/RustCrypto/password-hashes/pull/126

## 0.1.0 (2021-01-29)
- Initial release
