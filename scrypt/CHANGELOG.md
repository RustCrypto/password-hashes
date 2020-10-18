# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.5.0 (2020-10-18)
### Changed
- Bump `crypto-mac` dependency to v0.10 ([#58])
- Use `salsa20`crate to implement Salsa20/8 ([#60])

[#60]: https://github.com/RustCrypto/password-hashing/pull/60
[#58]: https://github.com/RustCrypto/password-hashing/pull/58

## 0.4.1 (2020-08-24)
### Changed
- Minor documentation update ([#50])

[#50]: https://github.com/RustCrypto/password-hashing/pull/50

## 0.4.0 (2020-08-18)
### Changed
- Bump `pbkdf2` dependency to v0.5 ([#45])

[#45]: https://github.com/RustCrypto/password-hashing/pull/45

## 0.3.1 (2020-07-03)
### Fixed
- Enable `alloc` feature for `base64`. ([#38])
- Remove superflous `main()` in documentation ([#40]) 

[#38]: https://github.com/RustCrypto/password-hashing/pull/38
[#40]: https://github.com/RustCrypto/password-hashing/pull/40

## 0.3.0 (2020-06-10)
### Added
- `recommended` method for easy creation of recommended ScryptParam ([#28])
- `std` feature ([#32])
- `thread_rng` feature ([#33])

### Changed
- Code improvements ([#33])
- Bump `rand` to v0.7 ([#33])
- Bump `hmac` to v0.8 ([#30])
- Bump `sha2` to v0.9 ([#30])
- Bump `pbkdf2` to v0.4 ([#36])
- Bump `subtle` to v2 ([#13])
- MSRV 1.41+ ([#30])
- Upgrade to Rust 2018 edition ([#24])

[#36]: https://github.com/RustCrypto/password-hashing/pull/36
[#33]: https://github.com/RustCrypto/password-hashing/pull/33
[#32]: https://github.com/RustCrypto/password-hashing/pull/32
[#30]: https://github.com/RustCrypto/password-hashing/pull/30
[#28]: https://github.com/RustCrypto/password-hashing/pull/28
[#24]: https://github.com/RustCrypto/password-hashing/pull/24
[#13]: https://github.com/RustCrypto/password-hashing/pull/13

## 0.2.0 (2018-10-08)

## 0.1.2 (2018-08-30)

## 0.1.1 (2018-07-15)

## 0.1.0 (2018-06-30)
