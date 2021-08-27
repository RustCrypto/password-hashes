# RustCrypto: SHA-crypt password hash

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [SHA-crypt password hash based on SHA-512][1],
a legacy password hashing scheme supported by the [POSIX crypt C library][2].

Password hashes using this algorithm start with `$6$` when encoded using the
[PHC string format][3].

[Documentation][docs-link]

## Minimum Supported Rust Version

Rust **1.51** or higher.

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

[crate-image]: https://img.shields.io/crates/v/sha-crypt.svg
[crate-link]: https://crates.io/crates/sha-crypt
[docs-image]: https://docs.rs/sha-crypt/badge.svg
[docs-link]: https://docs.rs/sha-crypt/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.51+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260046-password-hashes
[build-image]: https://github.com/RustCrypto/password-hashes/workflows/sha-crypt/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/password-hashes/actions?query=workflow%3Asha-crypt

[//]: # (general links)

[1]: https://www.akkadia.org/drepper/SHA-crypt.txt
[2]: https://en.wikipedia.org/wiki/Crypt_(C)
[3]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
