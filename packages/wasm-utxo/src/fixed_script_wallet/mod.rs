/// This module contains code for the BitGo Fixed Script Wallets.
/// These are not based on descriptors.
mod wallet_keys;

pub mod wallet_scripts;

#[cfg(test)]
pub mod test_utils;

pub use wallet_keys::*;
pub use wallet_scripts::*;
use wasm_bindgen::prelude::*;

use crate::address::networks::AddressFormat;
use crate::error::WasmMiniscriptError;
use crate::try_from_js_value::TryFromJsValue;
use crate::utxolib_compat::Network;

#[wasm_bindgen]
pub struct FixedScriptWallet;

#[wasm_bindgen]
impl FixedScriptWallet {
    #[wasm_bindgen(js_name = outputScript)]
    pub fn output_script(
        keys: JsValue,
        chain: u32,
        index: u32,
    ) -> Result<Vec<u8>, WasmMiniscriptError> {
        let chain = Chain::try_from(chain)
            .map_err(|e| WasmMiniscriptError::new(&format!("Invalid chain: {}", e)))?;

        let xpubs = xpub_triple_from_jsvalue(&keys)?;
        let scripts = WalletScripts::from_xpubs(&xpubs, chain, index);
        Ok(scripts.output_script().to_bytes())
    }

    #[wasm_bindgen(js_name = address)]
    pub fn address(
        keys: JsValue,
        chain: u32,
        index: u32,
        network: JsValue,
    ) -> Result<String, WasmMiniscriptError> {
        let network = Network::try_from_js_value(&network)?;
        let xpubs = xpub_triple_from_jsvalue(&keys)?;
        let chain = Chain::try_from(chain)
            .map_err(|e| WasmMiniscriptError::new(&format!("Invalid chain: {}", e)))?;
        let scripts = WalletScripts::from_xpubs(&xpubs, chain, index);
        let script = scripts.output_script();
        let address = crate::address::utxolib_compat::from_output_script_with_network(
            &script,
            &network,
            AddressFormat::Default,
        )
        .map_err(|e| WasmMiniscriptError::new(&format!("Failed to generate address: {}", e)))?;
        Ok(address.to_string())
    }
}
