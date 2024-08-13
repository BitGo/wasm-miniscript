use miniscript::bitcoin::Psbt;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsError};

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
}
