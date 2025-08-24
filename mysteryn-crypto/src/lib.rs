#![forbid(unsafe_code)]
//#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
//#![doc(
//    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
//    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
//)]
#![warn(clippy::pedantic)] // Be pedantic by default
#![warn(clippy::integer_division_remainder_used)]
// Be judicious about using `/` and `%`
//#![allow(non_snake_case)] // Allow notation matching the spec
#![allow(clippy::clone_on_copy)] // Be explicit about moving data
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::doc_markdown)]
//#![warn(missing_docs)] // Require all public interfaces to be documented

pub mod did;
pub mod hash;
pub mod multikey;
pub mod prelude;

pub use hash::*;
pub use mysteryn_core::{
    RawSignature, attributes, base32precheck, key_traits, multibase, multicodec, result, varint,
};

#[cfg(target_arch = "wasm32")]
pub mod js;

#[cfg(all(test, target_family = "wasm", target_os = "unknown"))]
mod tests {
    use wasm_bindgen_test;
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
}

#[cfg(test)]
mod test;
