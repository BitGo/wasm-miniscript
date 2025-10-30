use crate::address::networks::AddressFormat;
use crate::address::utxolib_compat::{
    from_output_script_with_network, to_output_script_with_network, UtxolibNetwork,
};
use crate::wasm::try_from_js_value::TryFromJsValue;
use miniscript::bitcoin::Script;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

#[wasm_bindgen]
pub struct UtxolibCompatNamespace;

#[wasm_bindgen]
impl UtxolibCompatNamespace {
    /// Convert output script to address string
    ///
    /// # Arguments
    /// * `script` - The output script as a byte array
    /// * `network` - The UtxolibNetwork object from JavaScript
    /// * `format` - Optional address format: "default" or "cashaddr" (only applicable for Bitcoin Cash and eCash)
    #[wasm_bindgen]
    pub fn from_output_script(
        script: &[u8],
        network: JsValue,
        format: Option<String>,
    ) -> std::result::Result<String, JsValue> {
        let network = UtxolibNetwork::try_from_js_value(&network)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let script_obj = Script::from_bytes(script);

        let format_str = format.as_deref();
        let address_format = AddressFormat::from_optional_str(format_str)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        from_output_script_with_network(script_obj, &network, address_format)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Convert address string to output script
    ///
    /// # Arguments
    /// * `address` - The address string
    /// * `network` - The UtxolibNetwork object from JavaScript
    /// * `format` - Optional address format (currently unused for decoding as all formats are accepted)
    #[wasm_bindgen]
    pub fn to_output_script(
        address: &str,
        network: JsValue,
        format: Option<String>,
    ) -> std::result::Result<Vec<u8>, JsValue> {
        let network = UtxolibNetwork::try_from_js_value(&network)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        // Validate format parameter even though we don't use it for decoding
        if let Some(fmt) = format {
            let format_str = Some(fmt.as_str());
            AddressFormat::from_optional_str(format_str)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
        }

        to_output_script_with_network(address, &network)
            .map(|script| script.to_bytes())
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
