# RustCrypto: bcrypt-pbkdf

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the [`bcrypt_pbkdf`] password-based key derivation
function, a custom derivative of PBKDF2 [used in OpenSSH].

## About

`bcrypt_pbkdf` is a password-based key derivation function that uses a PBKDF2-style repeated
application of a hash function, but instead of using a standard hash function like SHA-2 it uses
a bcrypt-style core based on the Blowfish cipher. At its heart is a modified bcrypt operation
called "bhash" that repeatedly mixes the password and salt into Blowfish’s internal state and then
uses Blowfish to encrypt a fixed 256-bit constant, producing a block of output. This is
deliberately expensive to compute to thwart brute force attacks, with a user-controlled number of
rounds which control the compute cost of the derivation.

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

[crate-image]: https://img.shields.io/crates/v/bcrypt-pbkdf
[crate-link]: https://crates.io/crates/bcrypt-pbkdf
[docs-image]: https://docs.rs/bcrypt-pbkdf/badge.svg
[docs-link]: https://docs.rs/bcrypt-pbkdf/
[build-image]: https://github.com/RustCrypto/password-hashes/actions/workflows/bcrypt-pbkdf.yml/badge.svg
[build-link]: https://github.com/RustCrypto/password-hashes/actions/workflows/bcrypt-pbkdf.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260046-password-hashes

[//]: # (links)

[`bcrypt_pbkdf`]: https://web.archive.org/web/20251228225511/https://flak.tedunangst.com/post/bcrypt-pbkdf
[used in OpenSSH]: https://web.archive.org/web/20251231170734/https://flak.tedunangst.com/post/new-openssh-key-format-and-bcrypt-pbkdf
