# RustCrypto: yescrypt

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the [yescrypt] password-based key derivation function.

## About

yescrypt is a variant of the [scrypt] password-based key derivation function and finalist in the
[Password Hashing Competition]. It has been adopted by several Linux distributions for the system
password hashing function, including Fedora, Debian, Ubuntu, and Arch.

The algorithm is described in [yescrypt - a Password Hashing Competition submission][paper].

## ⚠️ Security Warning

The implementation contained in this crate has never been independently audited!

USE AT YOUR OWN RISK!

Note that this crate is in an early stage of implementation and may contain bugs or features which
do not work correctly.

## Minimum Supported Rust Version (MSRV) Policy

MSRV increases are not considered breaking changes and can happen in patch releases.

The crate MSRV accounts for all supported targets and crate feature combinations, excluding
explicitly unstable features.

## License

Licensed under either of:

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](https://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/yescrypt
[crate-link]: https://crates.io/crates/yescrypt
[docs-image]: https://docs.rs/yescrypt/badge.svg
[docs-link]: https://docs.rs/yescrypt/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260046-password-hashes
[build-image]: https://github.com/RustCrypto/password-hashes/actions/workflows/yescrypt.yml/badge.svg
[build-link]: https://github.com/RustCrypto/password-hashes/actions/workflows/yescrypt.yml 

[//]: # (links)

[yescrypt]: https://www.openwall.com/yescrypt/
[scrypt]: https://en.wikipedia.org/wiki/Scrypt
[Password Hashing Competition]: https://www.password-hashing.net/
[paper]: https://www.password-hashing.net/submissions/specs/yescrypt-v2.pdf
