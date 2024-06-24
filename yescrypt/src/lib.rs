#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![warn(
clippy::cast_lossless,
clippy::cast_possible_truncation,
clippy::cast_possible_wrap,
clippy::cast_precision_loss,
clippy::cast_sign_loss,
clippy::checked_conversions,
clippy::implicit_saturating_sub,
clippy::panic,
clippy::panic_in_result_fn,
clippy::unwrap_used,
//missing_docs,
rust_2018_idioms,
unused_lifetimes,
unused_qualifications
)]

pub mod common;
pub mod sha256;
pub mod yescrypt;
