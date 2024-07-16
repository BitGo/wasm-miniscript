mod traits;

use std::str::FromStr;
use miniscript::{bitcoin, bitcoin::XOnlyPublicKey, Descriptor, Legacy, Miniscript, Segwitv0, Tap};
use miniscript::bitcoin::PublicKey;
use wasm_bindgen::prelude::*;
use crate::traits::TryIntoJsValue;

fn wrap_err<T, E: std::fmt::Debug>(r: Result<T, E>) -> Result<T, JsValue> {
    r.map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}

enum WrapMiniscriptEnum {
    Tap(Miniscript<XOnlyPublicKey, Tap>),
    Segwit(Miniscript<PublicKey, Segwitv0>),
    Legacy(Miniscript<PublicKey, Legacy>),
}

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

#[wasm_bindgen]
pub struct WrapMiniscript(WrapMiniscriptEnum);

#[wasm_bindgen]
impl WrapMiniscript {
    #[wasm_bindgen(js_name = node)]
    pub fn node(&self) -> Result<JsValue, JsValue> {
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

#[wasm_bindgen]
pub fn miniscript_from_string(script: &str, context_type: &str) -> Result<WrapMiniscript, JsValue> {
    match context_type {
        "tap" => Ok(WrapMiniscript::from(wrap_err(Miniscript::<XOnlyPublicKey, Tap>::from_str(script))?)),
        "segwitv0" => Ok(WrapMiniscript::from(wrap_err(Miniscript::<PublicKey, Segwitv0>::from_str(script))?)),
        "legacy" => Ok(WrapMiniscript::from(wrap_err(Miniscript::<PublicKey, Legacy>::from_str(script))?)),
        _ => Err(JsValue::from_str("Invalid context type"))
    }
}

#[wasm_bindgen]
pub fn miniscript_from_bitcoin_script(script: &[u8], context_type: &str) -> Result<WrapMiniscript, JsValue> {
    let script = bitcoin::Script::from_bytes(script);
    match context_type {
        "tap" => Ok(WrapMiniscript::from(wrap_err(Miniscript::<XOnlyPublicKey, Tap>::parse(script))?)),
        "segwitv0" => Ok(WrapMiniscript::from(wrap_err(Miniscript::<PublicKey, Segwitv0>::parse(script))?)),
        "legacy" => Ok(WrapMiniscript::from(wrap_err(Miniscript::<PublicKey, Legacy>::parse(script))?)),
        _ => Err(JsValue::from_str("Invalid context type"))
    }
}

#[wasm_bindgen]
pub struct WrapDescriptor(Descriptor<String>);

#[wasm_bindgen]
impl WrapDescriptor {
    pub fn node(&self) -> Result<JsValue, JsValue> {
        self.0.try_to_js_value()
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

#[wasm_bindgen]
pub fn descriptor_from_string(descriptor: &str) -> Result<WrapDescriptor, JsValue> {
    Ok(
        WrapDescriptor(Descriptor::<String>::from_str(descriptor)
            .map_err(|e| js_sys::Error::new(&format!("{:?}", e)))?))
}
