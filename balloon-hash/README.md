# RustCrypto: Balloon Hash

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the [Balloon] password hashing function.

## About

This crate contains an implementation of the Balloon password hashing
function as specified in the paper
[Balloon Hashing: A Memory-Hard Function Providing Provable Protection Against Sequential Attacks][paper].

This algorithm is first practical password hashing function that provides:

- Memory hardness which is proven in the random-oracle model
- Password-independent access
- Performance which meets or exceeds the best heuristically secure
  password-hashing algorithms

## Minimum Supported Rust Version

Rust **1.83** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/balloon-hash
[crate-link]: https://crates.io/crates/balloon-hash
[docs-image]: https://docs.rs/balloon-hash/badge.svg
[docs-link]: https://docs.rs/balloon-hash/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.83+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260046-password-hashes
[build-image]: https://github.com/RustCrypto/password-hashes/actions/workflows/balloon-hash.yml/badge.svg
[build-link]: https://github.com/RustCrypto/password-hashes/actions/workflows/balloon-hash.yml

[//]: # (general links)

[Balloon]: https://en.wikipedia.org/wiki/Balloon_hashing
[Paper]: https://eprint.iacr.org/2016/027.pdf
