use crate::descriptor::WrapDescriptorEnum;
use crate::try_into_js_value::TryIntoJsValue;
use crate::WrapDescriptor;
use miniscript::bitcoin::secp256k1::Secp256k1;
use miniscript::bitcoin::Psbt;
use miniscript::psbt::PsbtExt;
use std::str::FromStr;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsError, JsValue};

#[wasm_bindgen]
pub struct WrapPsbt(Psbt);

#[wasm_bindgen()]
impl WrapPsbt {
    pub fn deserialize(psbt: Vec<u8>) -> Result<WrapPsbt, JsError> {
        Ok(WrapPsbt(Psbt::deserialize(&psbt).map_err(JsError::from)?))
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize()
    }

    pub fn clone(&self) -> WrapPsbt {
        WrapPsbt(self.0.clone())
    }

    #[wasm_bindgen(js_name = updateInputWithDescriptor)]
    pub fn update_input_with_descriptor(
        &mut self,
        input_index: usize,
        descriptor: &WrapDescriptor,
    ) -> Result<(), JsError> {
        match &descriptor.0 {
            WrapDescriptorEnum::Definite(d) => self
                .0
                .update_input_with_descriptor(input_index, &d)
                .map_err(JsError::from),
            WrapDescriptorEnum::Derivable(_, _) => Err(JsError::new(
                "Cannot update input with a derivable descriptor",
            )),
            WrapDescriptorEnum::String(_) => {
                Err(JsError::new("Cannot update input with a string descriptor"))
            }
        }
    }

    #[wasm_bindgen(js_name = updateOutputWithDescriptor)]
    pub fn update_output_with_descriptor(
        &mut self,
        output_index: usize,
        descriptor: &WrapDescriptor,
    ) -> Result<(), JsError> {
        match &descriptor.0 {
            WrapDescriptorEnum::Definite(d) => self
                .0
                .update_output_with_descriptor(output_index, &d)
                .map_err(JsError::from),
            WrapDescriptorEnum::Derivable(_, _) => Err(JsError::new(
                "Cannot update output with a derivable descriptor",
            )),
            WrapDescriptorEnum::String(_) => Err(JsError::new(
                "Cannot update output with a string descriptor",
            )),
        }
    }

    #[wasm_bindgen(js_name = signWithXprv)]
    pub fn sign_with_xprv(&mut self, xprv: String) -> Result<JsValue, JsError> {
        let key = miniscript::bitcoin::bip32::Xpriv::from_str(&xprv)
            .map_err(|_| JsError::new("Invalid xprv"))?;
        self.0
            .sign(&key, &Secp256k1::new())
            .map_err(|(_, errors)| JsError::new(&format!("{} errors: {:?}", errors.len(), errors)))
            .and_then(|r| r.try_to_js_value())
    }

    #[wasm_bindgen(js_name = finalize)]
    pub fn finalize_mut(&mut self) -> Result<(), JsError> {
        self.0
            .finalize_mut(&Secp256k1::verification_only())
            .map_err(|vec_err| JsError::new(&format!("{} errors: {:?}", vec_err.len(), vec_err)))
    }
}
