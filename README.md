# RustCrypto: password hashing ![Rust Version][rustc-image] [![Project Chat][chat-image]][chat-link]

Collection of password hashing algorithms, otherwise known as password-based key
derivation functions, written in pure Rust.

## Supported algorithms

| Name      | Crates.io  | Documentation  |
| --------- |:----------:| :-----:|
| [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2)  | [![crates.io](https://img.shields.io/crates/v/pbkdf2.svg)](https://crates.io/crates/pbkdf2) | [![Documentation](https://docs.rs/pbkdf2/badge.svg)](https://docs.rs/pbkdf2) |
| [scrypt](https://en.wikipedia.org/wiki/Scrypt)  | [![crates.io](https://img.shields.io/crates/v/scrypt.svg)](https://crates.io/crates/scrypt) | [![Documentation](https://docs.rs/scrypt/badge.svg)](https://docs.rs/scrypt) |
| [SHA-crypt](https://www.akkadia.org/drepper/SHA-crypt.txt)    | [![crates.io](https://img.shields.io/crates/v/sha-crypt.svg)](https://crates.io/crates/sha-crypt) | [![Documentation](https://docs.rs/sha-crypt/badge.svg)](https://docs.rs/sha-crypt) |
| [bcrypt-pbkdf](https://flak.tedunangst.com/post/bcrypt-pbkdf) | [![crates.io](https://img.shields.io/crates/v/bcrypt-pbkdf.svg)](https://crates.io/crates/bcrypt-pbkdf) | [![Documentation](https://docs.rs/bcrypt-pbkdf/badge.svg)](https://docs.rs/bcrypt-pbkdf) |

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
