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
    #[error("Invalid input length")]
    InvalidInputLength,
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
impl From<Error> for JsValue {
    fn from(error: Error) -> Self {
        JsValue::from_str(&error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        assert_eq!(
            Error::EncodingError("test".to_string()).to_string(),
            "Encoding error: test"
        );
        assert_eq!(
            Error::ValidationError("test".to_string()).to_string(),
            "Validation error: test"
        );
        assert_eq!(
            Error::InvalidKey("test".to_string()).to_string(),
            "Invalid key: test"
        );
        assert_eq!(
            Error::InvalidSignature("test".to_string()).to_string(),
            "Signature verification failed: test"
        );
        assert_eq!(
            Error::InvalidToken("test".to_string()).to_string(),
            "Token verification failed: test"
        );
        assert_eq!(
            Error::IOError("test".to_string()).to_string(),
            "I/O error: test"
        );
    }
}
