# [RustCrypto]: Password Authentication

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Password authentication library with a focus on simplicity and ease-of-use,
with support for [Argon2], [PBKDF2], and [scrypt] password hashing algorithms.

## About

`password-auth` is a high-level password authentication library with a simple
interface which eliminates as much complexity and user choice as possible.

It wraps pure Rust implementations of multiple password hashing algorithms
maintained by the [RustCrypto] organization, with the goal of providing a
stable interface while allowing the password hashing algorithm implementations
to evolve at a faster pace.

## Usage

The core API consists of two functions:

- [`generate_hash`]: generates a password hash from the provided password. The
- [`verify_password`]: verifies the provided password against a password hash,
  returning an error if the password is incorrect.

Behind the scenes the crate uses the multi-algorithm support in the
[`password-hash`] crate to support multiple password hashing algorithms
simultaneously. By default it supports Argon2 (using the latest OWASP
recommended parameters 8), but it can also optionally support PBKDF2 and scrypt
by enabling crate features.

When multiple algorithms are enabled, it will still default to Argon2 for
`generate_hash`, but will be able to verify password hashes from PBKDF2 and
scrypt as well, if you have them in your password database.

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

[crate-image]: https://img.shields.io/crates/v/password-auth
[crate-link]: https://crates.io/crates/password-auth
[docs-image]: https://docs.rs/password-auth/badge.svg
[docs-link]: https://docs.rs/password-auth/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.81+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260046-password-hashes
[build-image]: https://github.com/RustCrypto/password-hashes/workflows/password-auth/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/password-hashes/actions?query=workflow%3Apassword-auth

[//]: # (general links)

[RustCrypto]: https://github.com/RustCrypto/
[Argon2]: https://en.wikipedia.org/wiki/Argon2
[PBKDF2]: https://en.wikipedia.org/wiki/PBKDF2
[scrypt]: https://en.wikipedia.org/wiki/Scrypt
[`generate_hash`]: https://docs.rs/password-auth/latest/password_auth/fn.generate_hash.html
[`verify_password`]: https://docs.rs/password-auth/latest/password_auth/fn.verify_password.html
[`password-hash`]: https://docs.rs/password-hash/latest/password_hash/
