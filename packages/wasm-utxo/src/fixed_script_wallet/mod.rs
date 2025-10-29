/// This module contains code for the BitGo Fixed Script Wallets.
/// These are not based on descriptors.
mod bip32interface;
mod wallet_keys;

pub mod wallet_scripts;

#[cfg(test)]
pub mod test_utils;

pub use wallet_keys::*;
pub use wallet_scripts::*;
use wasm_bindgen::prelude::*;

use crate::address::networks::{AddressFormat};
use crate::error::WasmMiniscriptError;
use crate::try_from_js_value::TryFromJsValue;
use crate::utxolib_compat::Network;

#[wasm_bindgen]
pub struct FixedScriptWalletNamespace;

#[wasm_bindgen]
impl FixedScriptWalletNamespace {
    #[wasm_bindgen]
    pub fn output_script(
        keys: JsValue,
        chain: u32,
        index: u32,
        network: JsValue,
    ) -> Result<Vec<u8>, WasmMiniscriptError> {
        let network = Network::try_from_js_value(&network)?;
        let chain = Chain::try_from(chain)
            .map_err(|e| WasmMiniscriptError::new(&format!("Invalid chain: {}", e)))?;

        let wallet_keys = RootWalletKeys::from_jsvalue(&keys)?;
        let scripts = WalletScripts::from_wallet_keys(&wallet_keys, chain, index, &network.output_script_support())?;
        Ok(scripts.output_script().to_bytes())
    }

    #[wasm_bindgen]
    pub fn address(
        keys: JsValue,
        chain: u32,
        index: u32,
        network: JsValue,
        address_format: Option<String>,
    ) -> Result<String, WasmMiniscriptError> {
        let network = Network::try_from_js_value(&network)?;
        let wallet_keys = RootWalletKeys::from_jsvalue(&keys)?;
        let chain = Chain::try_from(chain)
            .map_err(|e| WasmMiniscriptError::new(&format!("Invalid chain: {}", e)))?;
        let scripts = WalletScripts::from_wallet_keys(&wallet_keys, chain, index, &network.output_script_support())?;
        let script = scripts.output_script();
        let address_format = AddressFormat::from_optional_str(address_format.as_deref())
            .map_err(|e| WasmMiniscriptError::new(&format!("Invalid address format: {}", e)))?;
        let address = crate::address::utxolib_compat::from_output_script_with_network(
            &script,
            &network,
            address_format,
        )
        .map_err(|e| WasmMiniscriptError::new(&format!("Failed to generate address: {}", e)))?;
        Ok(address.to_string())
    }
}
