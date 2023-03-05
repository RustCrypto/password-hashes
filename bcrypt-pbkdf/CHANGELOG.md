# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.10.0 (2023-03-04)
### Added
- Support for `alloc`-free usage ([#372])

### Changed
- Bump `pbkdf2` dependency to v0.12; MSRV 1.60 ([#393])

[#372]: https://github.com/RustCrypto/password-hashes/pull/372
[#393]: https://github.com/RustCrypto/password-hashes/pull/393

## 0.9.0 (2022-03-18)
### Changed
- 2021 edition upgrade ([#284])
- Bump `pbkdf2` dependency to v0.11; MSRV 1.57 ([#291])

[#284]: https://github.com/RustCrypto/password-hashes/pull/284
[#291]: https://github.com/RustCrypto/password-hashes/pull/291

## 0.8.1 (2022-02-20)
### Changed
- Change `passphrase` to be `impl AsRef<[u8]>` allowing non-UTF8 passphrases ([#277])

[#277]: https://github.com/RustCrypto/password-hashes/pull/277

## 0.8.0 (2022-02-17)
### Changed
- Bump `blowfish` dependency to v0.9, edition to 2021, and MSRV to 1.56 ([#273])

[#273]: https://github.com/RustCrypto/password-hashes/pull/273

## 0.7.2 (2021-11-25)
### Changed
- Bump `sha2` and `pbkdf2` dependencies to v0.10 ([#254])

[#254]: https://github.com/RustCrypto/password-hashes/pull/254

## 0.7.1 (2021-08-27)
### Changed
- Bump `pbkdf2` dependency to v0.9 ([#223])

[#223]: https://github.com/RustCrypto/password-hashes/pull/223

## 0.7.0 (2021-08-27) [YANKED]
### Changed
- Relax `zeroize` requirements ([#195])
- Use `resolver = "2"`; MSRV 1.51+ ([#220])

[#195]: https://github.com/RustCrypto/password-hashes/pull/195
[#220]: https://github.com/RustCrypto/password-hashes/pull/220

## 0.6.2 (2021-07-20)
### Changed
- Pin `zeroize` dependency to v1.3 ([#190])

[#190]: https://github.com/RustCrypto/password-hashes/pull/190

## 0.6.1 (2021-05-04)
### Changed
- Bump `blowfish` dependency to v0.8 ([#171])

[#171]: https://github.com/RustCrypto/password-hashing/pull/171

## 0.6.0 (2021-04-29) [YANKED]
### Changed
- Bump `crypto-mac` dependency to v0.11 ([#165])
- Bump `pbkdf2` to v0.8 ([#167])

[#165]: https://github.com/RustCrypto/password-hashing/pull/165
[#167]: https://github.com/RustCrypto/password-hashing/pull/167

## 0.5.0 (2021-01-29)
### Changed
- Bump `pbkdf2` dependency to v0.7 ([#102])

[#102]: https://github.com/RustCrypto/password-hashing/pull/102

## 0.4.0 (2020-10-18)
### Changed
- Bump `crypto-mac` dependency to v0.10 ([#58])
- Bump `pbkdf2` dependency to v0.10 ([#61])

[#61]: https://github.com/RustCrypto/password-hashing/pull/61
[#58]: https://github.com/RustCrypto/password-hashing/pull/58

## 0.3.0 (2020-08-18)
### Changed
- Bump `crypto-mac` dependency to v0.9, `blowfish` to v0.6, and `pbkdf2` to v0.5 ([#46])

[#46]: https://github.com/RustCrypto/password-hashing/pull/46

## 0.2.1 (2020-06-03)
### Added
- `no_std` support ([#41])

[#41]: https://github.com/RustCrypto/password-hashing/pull/41

## 0.2.0 (2020-05-13)
### Changed
- Update dependencies to `sha2 v0.9`, `pbkdf2 v0.4`, `blowfish v0.5`,
and `crypto-mac v0.8`

## 0.1.0 (2020-01-03)
- Initial release
