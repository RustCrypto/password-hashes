# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
