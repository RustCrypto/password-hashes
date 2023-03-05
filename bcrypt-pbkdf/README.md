# RustCrypto: bcrypt-pbkdf

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the [`bcrypt_pbkdf`] password-based key derivation
function, a custom derivative of PBKDF2 [used in OpenSSH].

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

[crate-image]: https://buildstats.info/crate/bcrypt-pbkdf
[crate-link]: https://crates.io/crates/bcrypt-pbkdf
[docs-image]: https://docs.rs/bcrypt-pbkdf/badge.svg
[docs-link]: https://docs.rs/bcrypt-pbkdf/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.60+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260046-password-hashes
[build-image]: https://github.com/RustCrypto/password-hashes/workflows/bcrypt-pbkdf/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/password-hashes/actions?query=workflow%3Abcrypt-pbkdf

[//]: # (links)

[`bcrypt_pbkdf`]: https://flak.tedunangst.com/post/bcrypt-pbkdf
[used in OpenSSH]: https://flak.tedunangst.com/post/new-openssh-key-format-and-bcrypt-pbkdf
