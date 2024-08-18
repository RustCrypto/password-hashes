# RustCrypto: yescrypt

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the [yescrypt] password hashing function.

[Documentation][docs-link]

## ⚠️ Security Warning

The implementation contained in this crate has never been independently audited!

USE AT YOUR OWN RISK!

## Minimum Supported Rust Version

Rust **1.72** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

## License

Licensed under the BSD 2-clause license. See file [LICENSE] for more information.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://buildstats.info/crate/yescrypt
[crate-link]: https://crates.io/crates/yescrypt
[docs-image]: https://docs.rs/yescrypt/badge.svg
[docs-link]: https://docs.rs/yescrypt/
[license-image]: https://img.shields.io/crates/l/yescrypt?style=flat-square
[rustc-image]: https://img.shields.io/badge/rustc-1.60+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260046-password-hashes
[build-image]: https://github.com/RustCrypto/password-hashes/actions/workflows/yescrypt.yml/badge.svg
[build-link]: https://github.com/RustCrypto/password-hashes/actions/workflows/yescrypt.yml 

[//]: # (links)

[yescrypt]: https://www.openwall.com/yescrypt/
[LICENSE]: ./LICENSE
