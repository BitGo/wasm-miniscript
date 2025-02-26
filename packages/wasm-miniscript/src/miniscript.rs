use crate::error::WasmMiniscriptError;
use crate::try_into_js_value::TryIntoJsValue;
use miniscript::bitcoin::{PublicKey, XOnlyPublicKey};
use miniscript::{bitcoin, Legacy, Miniscript, Segwitv0, Tap};
use std::str::FromStr;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

// Define the macro to simplify operations on WrapMiniscriptEnum variants
// apply a func to the miniscript variant
macro_rules! unwrap_apply {
    ($self:expr, |$ms:ident| $func:expr) => {
        match $self {
            WrapMiniscriptEnum::Tap($ms) => $func,
            WrapMiniscriptEnum::Segwit($ms) => $func,
            WrapMiniscriptEnum::Legacy($ms) => $func,
        }
    };
}

pub enum WrapMiniscriptEnum {
    Tap(Miniscript<XOnlyPublicKey, Tap>),
    Segwit(Miniscript<PublicKey, Segwitv0>),
    Legacy(Miniscript<PublicKey, Legacy>),
}

#[wasm_bindgen]
pub struct WrapMiniscript(WrapMiniscriptEnum);

#[wasm_bindgen]
impl WrapMiniscript {
    #[wasm_bindgen(js_name = node)]
    pub fn node(&self) -> Result<JsValue, WasmMiniscriptError> {
        unwrap_apply!(&self.0, |ms| ms.try_to_js_value())
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        unwrap_apply!(&self.0, |ms| ms.to_string())
    }

    #[wasm_bindgen(js_name = encode)]
    pub fn encode(&self) -> Vec<u8> {
        unwrap_apply!(&self.0, |ms| ms.encode().into_bytes())
    }

    #[wasm_bindgen(js_name = toAsmString)]
    pub fn to_asm_string(&self) -> Result<String, WasmMiniscriptError> {
        unwrap_apply!(&self.0, |ms| Ok(ms.encode().to_asm_string()))
    }

    #[wasm_bindgen(js_name = fromString, skip_typescript)]
    pub fn from_string(
        script: &str,
        context_type: &str,
    ) -> Result<WrapMiniscript, WasmMiniscriptError> {
        match context_type {
            "tap" => Ok(WrapMiniscript::from(
                Miniscript::<XOnlyPublicKey, Tap>::from_str(script)
                    .map_err(WasmMiniscriptError::from)?,
            )),
            "segwitv0" => Ok(WrapMiniscript::from(
                Miniscript::<PublicKey, Segwitv0>::from_str(script)
                    .map_err(WasmMiniscriptError::from)?,
            )),
            "legacy" => Ok(WrapMiniscript::from(
                Miniscript::<PublicKey, Legacy>::from_str(script)
                    .map_err(WasmMiniscriptError::from)?,
            )),
            _ => Err(WasmMiniscriptError::new("Invalid context type")),
        }
    }

    #[wasm_bindgen(js_name = fromBitcoinScript, skip_typescript)]
    pub fn from_bitcoin_script(
        script: &[u8],
        context_type: &str,
    ) -> Result<WrapMiniscript, WasmMiniscriptError> {
        let script = bitcoin::Script::from_bytes(script);
        match context_type {
            "tap" => Ok(WrapMiniscript::from(
                Miniscript::<XOnlyPublicKey, Tap>::parse(script)
                    .map_err(WasmMiniscriptError::from)?,
            )),
            "segwitv0" => Ok(WrapMiniscript::from(
                Miniscript::<PublicKey, Segwitv0>::parse(script)
                    .map_err(WasmMiniscriptError::from)?,
            )),
            "legacy" => Ok(WrapMiniscript::from(
                Miniscript::<PublicKey, Legacy>::parse(script)
                    .map_err(WasmMiniscriptError::from)?,
            )),
            _ => Err(WasmMiniscriptError::new("Invalid context type")),
        }
    }
}

impl From<Miniscript<XOnlyPublicKey, Tap>> for WrapMiniscript {
    fn from(miniscript: Miniscript<XOnlyPublicKey, Tap>) -> Self {
        WrapMiniscript(WrapMiniscriptEnum::Tap(miniscript))
    }
}

impl From<Miniscript<PublicKey, Segwitv0>> for WrapMiniscript {
    fn from(miniscript: Miniscript<PublicKey, Segwitv0>) -> Self {
        WrapMiniscript(WrapMiniscriptEnum::Segwit(miniscript))
    }
}

impl From<Miniscript<PublicKey, Legacy>> for WrapMiniscript {
    fn from(miniscript: Miniscript<PublicKey, Legacy>) -> Self {
        WrapMiniscript(WrapMiniscriptEnum::Legacy(miniscript))
    }
}
