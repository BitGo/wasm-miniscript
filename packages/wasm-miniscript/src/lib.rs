mod traits;

use crate::traits::TryIntoJsValue;
use miniscript::bitcoin::secp256k1::Secp256k1;
use miniscript::bitcoin::{PublicKey, ScriptBuf};
use miniscript::descriptor::KeyMap;
use miniscript::{
    bitcoin, bitcoin::XOnlyPublicKey, DefiniteDescriptorKey, Descriptor, DescriptorPublicKey,
    Legacy, Miniscript, Segwitv0, Tap,
};
use std::fmt;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

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
    pub fn node(&self) -> Result<JsValue, JsError> {
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
    pub fn to_asm_string(&self) -> Result<String, JsError> {
        unwrap_apply!(&self.0, |ms| Ok(ms.encode().to_asm_string()))
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
        "tap" => Ok(WrapMiniscript::from(wrap_err(Miniscript::<
            XOnlyPublicKey,
            Tap,
        >::from_str(script))?)),
        "segwitv0" => Ok(WrapMiniscript::from(wrap_err(Miniscript::<
            PublicKey,
            Segwitv0,
        >::from_str(script))?)),
        "legacy" => Ok(WrapMiniscript::from(wrap_err(Miniscript::<
            PublicKey,
            Legacy,
        >::from_str(script))?)),
        _ => Err(JsValue::from_str("Invalid context type")),
    }
}

#[wasm_bindgen]
pub fn miniscript_from_bitcoin_script(
    script: &[u8],
    context_type: &str,
) -> Result<WrapMiniscript, JsValue> {
    let script = bitcoin::Script::from_bytes(script);
    match context_type {
        "tap" => Ok(WrapMiniscript::from(wrap_err(Miniscript::<
            XOnlyPublicKey,
            Tap,
        >::parse(script))?)),
        "segwitv0" => Ok(WrapMiniscript::from(wrap_err(Miniscript::<
            PublicKey,
            Segwitv0,
        >::parse(script))?)),
        "legacy" => Ok(WrapMiniscript::from(wrap_err(Miniscript::<
            PublicKey,
            Legacy,
        >::parse(script))?)),
        _ => Err(JsValue::from_str("Invalid context type")),
    }
}

enum WrapDescriptorEnum {
    Derivable(Descriptor<DescriptorPublicKey>, KeyMap),
    Definite(Descriptor<DefiniteDescriptorKey>),
    String(Descriptor<String>),
}

#[wasm_bindgen]
pub struct WrapDescriptor(WrapDescriptorEnum);

#[wasm_bindgen]
impl WrapDescriptor {
    pub fn node(&self) -> Result<JsValue, JsError> {
        Ok(match &self.0 {
            WrapDescriptorEnum::Derivable(desc, _) => desc.try_to_js_value()?,
            WrapDescriptorEnum::Definite(desc) => desc.try_to_js_value()?,
            WrapDescriptorEnum::String(desc) => desc.try_to_js_value()?,
        })
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        match &self.0 {
            WrapDescriptorEnum::Derivable(desc, _) => desc.to_string(),
            WrapDescriptorEnum::Definite(desc) => desc.to_string(),
            WrapDescriptorEnum::String(desc) => desc.to_string(),
        }
    }

    #[wasm_bindgen(js_name = hasWildcard)]
    pub fn has_wildcard(&self) -> bool {
        match &self.0 {
            WrapDescriptorEnum::Derivable(desc, _) => desc.has_wildcard(),
            WrapDescriptorEnum::Definite(_) => false,
            WrapDescriptorEnum::String(_) => false,
        }
    }

    #[wasm_bindgen(js_name = atDerivationIndex)]
    pub fn at_derivation_index(&self, index: u32) -> Result<WrapDescriptor, JsError> {
        match &self.0 {
            WrapDescriptorEnum::Derivable(desc, _keys) => {
                let d = desc.at_derivation_index(index)?;
                Ok(WrapDescriptor(WrapDescriptorEnum::Definite(d)))
            }
            _ => Err(JsError::new("Cannot derive from a definite descriptor")),
        }
    }

    fn explicit_script(&self) -> Result<ScriptBuf, JsError> {
        match &self.0 {
            WrapDescriptorEnum::Definite(desc) => {
                Ok(desc.explicit_script()?)
            }
            WrapDescriptorEnum::Derivable(_, _) => {
                Err(JsError::new("Cannot encode a derivable descriptor"))
            }
            WrapDescriptorEnum::String(_) => Err(JsError::new("Cannot encode a string descriptor")),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, JsError> {
        Ok(self.explicit_script()?.to_bytes())
    }

    #[wasm_bindgen(js_name = toAsmString)]
    pub fn to_asm_string(&self) -> Result<String, JsError> {
        Ok(self.explicit_script()?.to_asm_string())
    }
}

#[wasm_bindgen]
pub fn descriptor_from_string(descriptor: &str, pk_type: &str) -> Result<WrapDescriptor, JsError> {
    match pk_type {
        "derivable" => {
            let secp = Secp256k1::new();
            let (desc, keys) = Descriptor::parse_descriptor(&secp, descriptor)?;
            Ok(WrapDescriptor(WrapDescriptorEnum::Derivable(desc, keys)))
        }
        "definite" => {
            let desc = Descriptor::<DefiniteDescriptorKey>::from_str(descriptor)?;
            Ok(WrapDescriptor(WrapDescriptorEnum::Definite(desc)))
        }
        "string" => {
            let desc = Descriptor::<String>::from_str(descriptor)?;
            Ok(WrapDescriptor(WrapDescriptorEnum::String(desc)))
        }
        _ => Err(JsError::new("Invalid descriptor type")),
    }
}


#[test]
pub fn panic_xprv() {

    let (d,m) = Descriptor::parse_descriptor(
        &Secp256k1::new(),
        "wsh(multi(2,xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0,xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*,xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'))",
    ).unwrap();

    let dd = d.at_derivation_index(0).unwrap();

    let _ = dd.explicit_script().unwrap();
}