# RustCrypto: Password Authentication

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Password authentication library with a focus on simplicity and ease-of-use,
with support for [Argon2], [PBKDF2], and [scrypt] password hashing algorithms.

[Documentation][docs-link]

## Minimum Supported Rust Version

Rust **1.60** or higher.

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

[crate-image]: https://buildstats.info/crate/password-auth
[crate-link]: https://crates.io/crates/password-auth
[docs-image]: https://docs.rs/password-auth/badge.svg
[docs-link]: https://docs.rs/password-auth/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.60+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260046-password-hashes
[build-image]: https://github.com/RustCrypto/password-hashes/workflows/password-auth/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/password-hashes/actions?query=workflow%3Apassword-auth

[//]: # (general links)

[Argon2]: https://en.wikipedia.org/wiki/Argon2
[PBKDF2]: https://en.wikipedia.org/wiki/PBKDF2
[scrypt]: https://en.wikipedia.org/wiki/Scrypt
