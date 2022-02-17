# RustCrypto: Password Hashes

[![Project Chat][chat-image]][chat-link]
[![dependency status][deps-image]][deps-link]
![Apache2/MIT licensed][license-image]

Collection of password hashing algorithms, otherwise known as password-based key derivation functions, written in pure Rust.

## Supported Algorithms

| Algorithm | Crate            | Crates.io  | Documentation | MSRV |
|-----------|------------------|:----------:|:-------------:|:----:|
| [Argon2] | [`argon2`]       | [![crates.io](https://img.shields.io/crates/v/argon2.svg)](https://crates.io/crates/argon2) | [![Documentation](https://docs.rs/argon2/badge.svg)](https://docs.rs/argon2) | ![MSRV 1.51][msrv-1.51] |
| [Balloon] | [`balloon-hash`] | [![crates.io](https://img.shields.io/crates/v/balloon-hash.svg)](https://crates.io/crates/balloon-hash) | [![Documentation](https://docs.rs/balloon-hash/badge.svg)](https://docs.rs/balloon-hash) | ![MSRV 1.56][msrv-1.56] |
| [bcrypt-pbkdf] | [`bcrypt-pbkdf`] |[![crates.io](https://img.shields.io/crates/v/bcrypt-pbkdf.svg)](https://crates.io/crates/bcrypt-pbkdf) | [![Documentation](https://docs.rs/bcrypt-pbkdf/badge.svg)](https://docs.rs/bcrypt-pbkdf) | ![MSRV 1.56][msrv-1.56] |
| [PBKDF2] | [`pbkdf2`]       | [![crates.io](https://img.shields.io/crates/v/pbkdf2.svg)](https://crates.io/crates/pbkdf2) | [![Documentation](https://docs.rs/pbkdf2/badge.svg)](https://docs.rs/pbkdf2) | ![MSRV 1.51][msrv-1.51] |
| [scrypt] | [`scrypt`]       | [![crates.io](https://img.shields.io/crates/v/scrypt.svg)](https://crates.io/crates/scrypt) | [![Documentation](https://docs.rs/scrypt/badge.svg)](https://docs.rs/scrypt) | ![MSRV 1.56][msrv-1.56] |
| [SHA-crypt] | [`sha-crypt`]    | [![crates.io](https://img.shields.io/crates/v/sha-crypt.svg)](https://crates.io/crates/sha-crypt) | [![Documentation](https://docs.rs/sha-crypt/badge.svg)](https://docs.rs/sha-crypt) | ![MSRV 1.51][msrv-1.51] |

Please see the [OWASP Password Storage Cheat Sheet] for assistance in selecting an appropriate algorithm for your use case.

### Minimum Supported Rust Version (MSRV) Policy

MSRV bumps are considered breaking changes and will be performed only with minor version bump.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260046-password-hashes
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[deps-image]: https://deps.rs/repo/github/RustCrypto/password-hashes/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/password-hashes
[msrv-1.51]: https://img.shields.io/badge/rustc-1.51.0+-blue.svg
[msrv-1.56]: https://img.shields.io/badge/rustc-1.56.0+-blue.svg

[//]: # (crates)

[`argon2`]: ./argon2
[`balloon-hash`]: ./balloon-hash
[`bcrypt-pbkdf`]: ./bcrypt-pbkdf
[`pbkdf2`]: ./pbkdf2
[`scrypt`]: ./scrypt
[`sha-crypt`]: ./sha-crypt

[//]: # (general links)

[Argon2]: https://en.wikipedia.org/wiki/Argon2
[Balloon]: https://en.wikipedia.org/wiki/Balloon_hashing
[bcrypt-pbkdf]: https://flak.tedunangst.com/post/bcrypt-pbkdf
[PBKDF2]: https://en.wikipedia.org/wiki/PBKDF2
[scrypt]: https://en.wikipedia.org/wiki/Scrypt
[SHA-crypt]: https://www.akkadia.org/drepper/SHA-crypt.txt
[OWASP Password Storage Cheat Sheet]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
