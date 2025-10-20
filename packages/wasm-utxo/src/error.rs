use core::fmt;

#[derive(Debug, Clone)]
pub enum WasmMiniscriptError {
    StringError(String),
}

impl std::error::Error for WasmMiniscriptError {}
impl fmt::Display for WasmMiniscriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WasmMiniscriptError::StringError(s) => write!(f, "{}", s),
        }
    }
}

impl From<&str> for WasmMiniscriptError {
    fn from(s: &str) -> Self {
        WasmMiniscriptError::StringError(s.to_string())
    }
}

impl From<String> for WasmMiniscriptError {
    fn from(s: String) -> Self {
        WasmMiniscriptError::StringError(s)
    }
}

impl From<miniscript::Error> for WasmMiniscriptError {
    fn from(err: miniscript::Error) -> Self {
        WasmMiniscriptError::StringError(err.to_string())
    }
}

impl From<miniscript::descriptor::ConversionError> for WasmMiniscriptError {
    fn from(err: miniscript::descriptor::ConversionError) -> Self {
        WasmMiniscriptError::StringError(err.to_string())
    }
}

impl WasmMiniscriptError {
    pub fn new(s: &str) -> WasmMiniscriptError {
        WasmMiniscriptError::StringError(s.to_string())
    }
}
