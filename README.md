# RustCrypto: password hashes ![Rust Version][rustc-image] [![Project Chat][chat-image]][chat-link] [![dependency status][deps-image]][deps-link]

Collection of password hashing algorithms, otherwise known as password-based key
derivation functions, written in pure Rust.

## Supported algorithms

| Name      | Crates.io  | Documentation | Build |
|-----------|------------|---------------|-------|
| [Argon2](https://en.wikipedia.org/wiki/Argon2)  | [![crates.io](https://img.shields.io/crates/v/argon2.svg)](https://crates.io/crates/argon2) | [![Documentation](https://docs.rs/argon2/badge.svg)](https://docs.rs/argon2) | ![Build](https://github.com/RustCrypto/password-hashes/workflows/argon2/badge.svg?branch=master&event=push) |
| [bcrypt-pbkdf](https://flak.tedunangst.com/post/bcrypt-pbkdf) | [![crates.io](https://img.shields.io/crates/v/bcrypt-pbkdf.svg)](https://crates.io/crates/bcrypt-pbkdf) | [![Documentation](https://docs.rs/bcrypt-pbkdf/badge.svg)](https://docs.rs/bcrypt-pbkdf) | ![Build](https://github.com/RustCrypto/password-hashes/workflows/bcrypt-pbkdf/badge.svg?branch=master&event=push) |
| [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2)  | [![crates.io](https://img.shields.io/crates/v/pbkdf2.svg)](https://crates.io/crates/pbkdf2) | [![Documentation](https://docs.rs/pbkdf2/badge.svg)](https://docs.rs/pbkdf2) | ![Build](https://github.com/RustCrypto/password-hashes/workflows/pbkdf2/badge.svg?branch=master&event=push) |
| [scrypt](https://en.wikipedia.org/wiki/Scrypt)  | [![crates.io](https://img.shields.io/crates/v/scrypt.svg)](https://crates.io/crates/scrypt) | [![Documentation](https://docs.rs/scrypt/badge.svg)](https://docs.rs/scrypt) | ![Build](https://github.com/RustCrypto/password-hashes/workflows/scrypt/badge.svg?branch=master&event=push) |
| [SHA-crypt](https://www.akkadia.org/drepper/SHA-crypt.txt)    | [![crates.io](https://img.shields.io/crates/v/sha-crypt.svg)](https://crates.io/crates/sha-crypt) | [![Documentation](https://docs.rs/sha-crypt/badge.svg)](https://docs.rs/sha-crypt) | ![Build](https://github.com/RustCrypto/password-hashes/workflows/sha-crypt/badge.svg?branch=master&event=push) |

Please see the [OWASP Password Storage Cheat Sheet] for assistance in selecting
an appropriate algorithm for your use case.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license

[//]: # (badges)

[rustc-image]: https://img.shields.io/badge/rustc-1.41+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260046-password-hashes
[deps-image]: https://deps.rs/repo/github/RustCrypto/password-hashes/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/password-hashes

[//]: # (general links)

[OWASP Password Storage Cheat Sheet]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
