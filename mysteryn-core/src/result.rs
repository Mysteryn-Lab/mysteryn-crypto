use thiserror::Error;
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
use wasm_bindgen::prelude::*;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Encoding error: {0}")]
    EncodingError(String),
    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Signature verification failed: {0}")]
    InvalidSignature(String),
    #[error("Token verification failed: {0}")]
    InvalidToken(String),

    #[error("I/O error: {0}")]
    IOError(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
impl From<Error> for JsValue {
    fn from(error: Error) -> Self {
        JsValue::from_str(&error.to_string())
    }
}
