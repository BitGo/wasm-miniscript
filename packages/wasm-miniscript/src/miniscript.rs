use miniscript::bitcoin::{PublicKey, XOnlyPublicKey};
use miniscript::{bitcoin, Legacy, Miniscript, Segwitv0, Tap};
use std::str::FromStr;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsError, JsValue};

use crate::try_into_js_value::TryIntoJsValue;

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
pub fn miniscript_from_string(script: &str, context_type: &str) -> Result<WrapMiniscript, JsError> {
    match context_type {
        "tap" => Ok(WrapMiniscript::from(
            Miniscript::<XOnlyPublicKey, Tap>::from_str(script).map_err(JsError::from)?,
        )),
        "segwitv0" => Ok(WrapMiniscript::from(
            Miniscript::<PublicKey, Segwitv0>::from_str(script).map_err(JsError::from)?,
        )),
        "legacy" => Ok(WrapMiniscript::from(
            Miniscript::<PublicKey, Legacy>::from_str(script).map_err(JsError::from)?,
        )),
        _ => Err(JsError::new("Invalid context type")),
    }
}

#[wasm_bindgen]
pub fn miniscript_from_bitcoin_script(
    script: &[u8],
    context_type: &str,
) -> Result<WrapMiniscript, JsError> {
    let script = bitcoin::Script::from_bytes(script);
    match context_type {
        "tap" => Ok(WrapMiniscript::from(
            Miniscript::<XOnlyPublicKey, Tap>::parse(script).map_err(JsError::from)?,
        )),
        "segwitv0" => Ok(WrapMiniscript::from(
            Miniscript::<PublicKey, Segwitv0>::parse(script).map_err(JsError::from)?,
        )),
        "legacy" => Ok(WrapMiniscript::from(
            Miniscript::<PublicKey, Legacy>::parse(script).map_err(JsError::from)?,
        )),
        _ => Err(JsError::new("Invalid context type")),
    }
}

#[test]
pub fn panic_xprv() {
    use miniscript::bitcoin::secp256k1::Secp256k1;
    use miniscript::Descriptor;
    let (d,m) = Descriptor::parse_descriptor(
        &Secp256k1::new(),
        "wsh(multi(2,xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0,xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*,xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'))",
    ).unwrap();

    let dd = d.at_derivation_index(0).unwrap();

    let _ = dd.explicit_script().unwrap();
}
