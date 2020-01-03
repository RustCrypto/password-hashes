# RustCrypto: password hashing
[![Build Status](https://travis-ci.org/RustCrypto/password-hashing.svg?branch=master)](https://travis-ci.org/RustCrypto/password-hashing) [![dependency status](https://deps.rs/repo/github/RustCrypto/password-hashing/status.svg)](https://deps.rs/repo/github/RustCrypto/password-hashing)

Collection of password hashing algorithms, otherwise known as password-based key
derivation functions, written in pure Rust.

## Supported algorithms

| Name      | Crates.io  | Documentation  |
| --------- |:----------:| :-----:|
| [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2)  | [![crates.io](https://img.shields.io/crates/v/pbkdf2.svg)](https://crates.io/crates/pbkdf2) | [![Documentation](https://docs.rs/pbkdf2/badge.svg)](https://docs.rs/pbkdf2) |
| [scrypt](https://en.wikipedia.org/wiki/Scrypt)  | [![crates.io](https://img.shields.io/crates/v/scrypt.svg)](https://crates.io/crates/scrypt) | [![Documentation](https://docs.rs/scrypt/badge.svg)](https://docs.rs/scrypt) |
| [bcrypt-pbkdf](https://flak.tedunangst.com/post/bcrypt-pbkdf)  | [![crates.io](https://img.shields.io/crates/v/bcrypt-pbkdf.svg)](https://crates.io/crates/bcrypt-pbkdf) | [![Documentation](https://docs.rs/bcrypt-pbkdf/badge.svg)](https://docs.rs/bcrypt-pbkdf) |

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license
