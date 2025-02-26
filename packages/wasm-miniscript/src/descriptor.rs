use crate::error::WasmMiniscriptError;
use crate::try_into_js_value::TryIntoJsValue;
use miniscript::bitcoin::secp256k1::Secp256k1;
use miniscript::bitcoin::ScriptBuf;
use miniscript::descriptor::KeyMap;
use miniscript::{DefiniteDescriptorKey, Descriptor, DescriptorPublicKey};
use std::str::FromStr;
use wasm_bindgen::prelude::*;

pub(crate) enum WrapDescriptorEnum {
    Derivable(Descriptor<DescriptorPublicKey>, KeyMap),
    Definite(Descriptor<DefiniteDescriptorKey>),
    String(Descriptor<String>),
}

#[wasm_bindgen]
pub struct WrapDescriptor(pub(crate) WrapDescriptorEnum);

#[wasm_bindgen]
impl WrapDescriptor {
    pub fn node(&self) -> Result<JsValue, WasmMiniscriptError> {
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
    pub fn at_derivation_index(&self, index: u32) -> Result<WrapDescriptor, WasmMiniscriptError> {
        match &self.0 {
            WrapDescriptorEnum::Derivable(desc, _keys) => {
                let d = desc.at_derivation_index(index)?;
                Ok(WrapDescriptor(WrapDescriptorEnum::Definite(d)))
            }
            _ => Err(WasmMiniscriptError::new(
                "Cannot derive from a definite descriptor",
            )),
        }
    }

    #[wasm_bindgen(js_name = descType)]
    pub fn desc_type(&self) -> Result<JsValue, WasmMiniscriptError> {
        (match &self.0 {
            WrapDescriptorEnum::Derivable(desc, _) => desc.desc_type(),
            WrapDescriptorEnum::Definite(desc) => desc.desc_type(),
            WrapDescriptorEnum::String(desc) => desc.desc_type(),
        })
        .try_to_js_value()
    }

    #[wasm_bindgen(js_name = scriptPubkey)]
    pub fn script_pubkey(&self) -> Result<Vec<u8>, WasmMiniscriptError> {
        match &self.0 {
            WrapDescriptorEnum::Definite(desc) => Ok(desc.script_pubkey().to_bytes()),
            _ => Err(WasmMiniscriptError::new("Cannot derive from a non-definite descriptor")),
        }
    }

    fn explicit_script(&self) -> Result<ScriptBuf, WasmMiniscriptError> {
        match &self.0 {
            WrapDescriptorEnum::Definite(desc) => Ok(desc.explicit_script()?),
            WrapDescriptorEnum::Derivable(_, _) => Err(WasmMiniscriptError::new(
                "Cannot encode a derivable descriptor",
            )),
            WrapDescriptorEnum::String(_) => Err(WasmMiniscriptError::new(
                "Cannot encode a string descriptor",
            )),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, WasmMiniscriptError> {
        Ok(self.explicit_script()?.to_bytes())
    }

    #[wasm_bindgen(js_name = toAsmString)]
    pub fn to_asm_string(&self) -> Result<String, WasmMiniscriptError> {
        Ok(self.explicit_script()?.to_asm_string())
    }

    #[wasm_bindgen(js_name = maxWeightToSatisfy)]
    pub fn max_weight_to_satisfy(&self) -> Result<u32, WasmMiniscriptError> {
        let weight = (match &self.0 {
            WrapDescriptorEnum::Derivable(desc, _) => desc.max_weight_to_satisfy(),
            WrapDescriptorEnum::Definite(desc) => desc.max_weight_to_satisfy(),
            WrapDescriptorEnum::String(desc) => desc.max_weight_to_satisfy(),
        })?;
        weight
            .to_wu()
            .try_into()
            .map_err(|_| WasmMiniscriptError::new("Weight exceeds u32"))
    }

    fn from_string_derivable(descriptor: &str) -> Result<WrapDescriptor, WasmMiniscriptError> {
        let secp = Secp256k1::new();
        let (desc, keys) = Descriptor::parse_descriptor(&secp, descriptor)?;
        Ok(WrapDescriptor(WrapDescriptorEnum::Derivable(desc, keys)))
    }

    fn from_string_definite(descriptor: &str) -> Result<WrapDescriptor, WasmMiniscriptError> {
        let desc = Descriptor::<DefiniteDescriptorKey>::from_str(descriptor)?;
        Ok(WrapDescriptor(WrapDescriptorEnum::Definite(desc)))
    }

    #[wasm_bindgen(js_name = fromString, skip_typescript)]
    pub fn from_string(
        descriptor: &str,
        pk_type: &str,
    ) -> Result<WrapDescriptor, WasmMiniscriptError> {
        match pk_type {
            "derivable" => WrapDescriptor::from_string_derivable(descriptor),
            "definite" => WrapDescriptor::from_string_definite(descriptor),
            "string" => {
                let desc = Descriptor::<String>::from_str(descriptor)?;
                Ok(WrapDescriptor(WrapDescriptorEnum::String(desc)))
            }
            _ => Err(WasmMiniscriptError::new("Invalid descriptor type")),
        }
    }
}