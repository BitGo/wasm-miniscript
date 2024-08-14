use std::error::Error;
use std::fmt;
use miniscript::bitcoin;

#[derive(Debug, Clone)]
enum WrapError {
    Miniscript(String),
    Bitcoin(String),
}

impl Error for WrapError {}

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