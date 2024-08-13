use wasm_bindgen::JsValue;
use std::fmt;
use miniscript::bitcoin;

#[derive(Debug, Clone)]
enum WrapError {
    Miniscript(String),
    Bitcoin(String),
}

impl std::error::Error for WrapError {}

impl fmt::Display for WrapError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WrapError::Miniscript(e) => write!(f, "Miniscript error: {}", e),
            WrapError::Bitcoin(e) => write!(f, "Bitcoin error: {}", e),
        }
    }
}

impl From<miniscript::Error> for WrapError {
    fn from(e: miniscript::Error) -> Self {
        WrapError::Miniscript(e.to_string())
    }
}

impl From<bitcoin::consensus::encode::Error> for WrapError {
    fn from(e: bitcoin::consensus::encode::Error) -> Self {
        WrapError::Bitcoin(e.to_string())
    }
}

pub fn wrap_err<T, E: std::fmt::Debug>(r: Result<T, E>) -> Result<T, JsValue> {
    r.map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}