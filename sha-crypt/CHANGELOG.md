# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.2 (2021-11-25)
### Changed
- Bump `sha2` dependency to v0.10 ([#254])

[#254]: https://github.com/RustCrypto/password-hashes/pull/254

## 0.3.1 (2021-09-17)
### Fixed
- Handle B64 decoding errors ([#242])

[#242]: https://github.com/RustCrypto/password-hashes/pull/242

## 0.3.0 (2021-08-27)
### Changed
- Use `resolver = "2"`; MSRV 1.51+ ([#220])

[#220]: https://github.com/RustCrypto/password-hashes/pull/220

## 0.2.1 (2021-07-20)
### Changed
- Pin `subtle` dependency to v2.4 ([#190])

[#190]: https://github.com/RustCrypto/password-hashes/pull/190

## 0.2.0 (2021-01-29)
### Changed
- Bump `rand` dependency to v0.8 ([#86])
- Rename `include_simple` feature to `simple` ([#99])
- Remove `Vec` from public API ([#113]) 
- MSRV 1.47+ ([#113])

[#86]: https://github.com/RustCrypto/password-hashing/pull/86
[#99]: https://github.com/RustCrypto/password-hashing/pull/99
[#113]: https://github.com/RustCrypto/password-hashing/pull/113

## 0.1.0 (2020-12-28)
- Initial release
