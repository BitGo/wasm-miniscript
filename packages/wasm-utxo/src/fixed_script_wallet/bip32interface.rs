use std::str::FromStr;

use crate::bitcoin::bip32::Xpub;
use crate::error::WasmMiniscriptError;
use crate::try_from_js_value::{get_buffer_field, get_field, get_nested_field};
use wasm_bindgen::JsValue;

fn try_xpub_from_bip32_properties(bip32_key: &JsValue) -> Result<Xpub, WasmMiniscriptError> {
    // Extract properties using helper functions
    let version: u32 = get_nested_field(bip32_key, "network.bip32.public")?;
    let depth: u8 = get_field(bip32_key, "depth")?;
    let parent_fingerprint: u32 = get_field(bip32_key, "parentFingerprint")?;
    let index: u32 = get_field(bip32_key, "index")?;
    let chain_code_bytes: [u8; 32] = get_buffer_field(bip32_key, "chainCode")?;
    let public_key_bytes: [u8; 33] = get_buffer_field(bip32_key, "publicKey")?;

    // Build BIP32 serialization (78 bytes total)
    let mut data = Vec::with_capacity(78);
    data.extend_from_slice(&version.to_be_bytes()); // 4 bytes: version
    data.push(depth); // 1 byte: depth
    data.extend_from_slice(&parent_fingerprint.to_be_bytes()); // 4 bytes: parent fingerprint
    data.extend_from_slice(&index.to_be_bytes()); // 4 bytes: index
    data.extend_from_slice(&chain_code_bytes); // 32 bytes: chain code
    data.extend_from_slice(&public_key_bytes); // 33 bytes: public key

    // Use the Xpub::decode method which properly handles network detection and constructs the Xpub
    Xpub::decode(&data)
        .map_err(|e| WasmMiniscriptError::new(&format!("Failed to decode xpub: {}", e)))
}

fn xpub_from_base58_method(bip32_key: &JsValue) -> Result<Xpub, WasmMiniscriptError> {
    // Fallback: Call toBase58() method on BIP32Interface
    let to_base58 = js_sys::Reflect::get(bip32_key, &JsValue::from_str("toBase58"))
        .map_err(|_| WasmMiniscriptError::new("Failed to get 'toBase58' method"))?;

    if !to_base58.is_function() {
        return Err(WasmMiniscriptError::new("'toBase58' is not a function"));
    }

    let to_base58_fn = js_sys::Function::from(to_base58);
    let xpub_str = to_base58_fn
        .call0(bip32_key)
        .map_err(|_| WasmMiniscriptError::new("Failed to call 'toBase58'"))?;

    let xpub_string = xpub_str
        .as_string()
        .ok_or_else(|| WasmMiniscriptError::new("'toBase58' did not return a string"))?;

    Xpub::from_str(&xpub_string)
        .map_err(|e| WasmMiniscriptError::new(&format!("Failed to parse xpub: {}", e)))
}

pub fn xpub_from_bip32interface(bip32_key: &JsValue) -> Result<Xpub, WasmMiniscriptError> {
    // Try to construct from properties first, fall back to toBase58() if that fails
    try_xpub_from_bip32_properties(bip32_key).or_else(|_| xpub_from_base58_method(bip32_key))
}
