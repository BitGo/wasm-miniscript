/// Helper structs for compatibility with npm @bitgo/utxo-lib
/// Long-term we should not use the `Network` objects from @bitgo/utxo-lib any longer,
/// but for now we need to keep this compatibility layer.
use wasm_bindgen::JsValue;

use crate::address::{bech32, cashaddr, AddressError, Base58CheckCodec};
use crate::bitcoin::{Script, ScriptBuf};

type Result<T> = std::result::Result<T, AddressError>;

pub struct CashAddr {
    pub prefix: String,
    pub pub_key_hash: u32,
    pub script_hash: u32,
}

pub struct Network {
    pub pub_key_hash: u32,
    pub script_hash: u32,
    pub cash_addr: Option<CashAddr>,
    pub bech32: Option<String>,
}

impl Network {
    /// Parse a Network object from a JavaScript value
    pub fn from_js_value(js_network: &JsValue) -> Result<Self> {
        // Helper to get a required number field
        let get_number = |key: &str| -> Result<u32> {
            let value =
                js_sys::Reflect::get(js_network, &JsValue::from_str(key)).map_err(|_| {
                    AddressError::InvalidAddress(format!(
                        "Failed to read {} from network object",
                        key
                    ))
                })?;

            value
                .as_f64()
                .ok_or_else(|| AddressError::InvalidAddress(format!("{} must be a number", key)))
                .map(|n| n as u32)
        };

        // Helper to get an optional string field
        let get_optional_string = |key: &str| -> Result<Option<String>> {
            let value =
                js_sys::Reflect::get(js_network, &JsValue::from_str(key)).map_err(|_| {
                    AddressError::InvalidAddress(format!(
                        "Failed to read {} from network object",
                        key
                    ))
                })?;

            if value.is_undefined() || value.is_null() {
                Ok(None)
            } else {
                value
                    .as_string()
                    .ok_or_else(|| {
                        AddressError::InvalidAddress(format!("{} must be a string", key))
                    })
                    .map(Some)
            }
        };

        let pub_key_hash = get_number("pubKeyHash")?;
        let script_hash = get_number("scriptHash")?;
        let bech32 = get_optional_string("bech32")?;

        // Parse optional cashAddr object
        let cash_addr = {
            let cash_addr_obj = js_sys::Reflect::get(js_network, &JsValue::from_str("cashAddr"))
                .map_err(|_| {
                    AddressError::InvalidAddress(
                        "Failed to read cashAddr from network object".to_string(),
                    )
                })?;

            if cash_addr_obj.is_undefined() || cash_addr_obj.is_null() {
                None
            } else {
                let prefix = js_sys::Reflect::get(&cash_addr_obj, &JsValue::from_str("prefix"))
                    .map_err(|_| {
                        AddressError::InvalidAddress("Failed to read cashAddr.prefix".to_string())
                    })?
                    .as_string()
                    .ok_or_else(|| {
                        AddressError::InvalidAddress("cashAddr.prefix must be a string".to_string())
                    })?;

                let pub_key_hash =
                    js_sys::Reflect::get(&cash_addr_obj, &JsValue::from_str("pubKeyHash"))
                        .map_err(|_| {
                            AddressError::InvalidAddress(
                                "Failed to read cashAddr.pubKeyHash".to_string(),
                            )
                        })?
                        .as_f64()
                        .ok_or_else(|| {
                            AddressError::InvalidAddress(
                                "cashAddr.pubKeyHash must be a number".to_string(),
                            )
                        })? as u32;

                let script_hash =
                    js_sys::Reflect::get(&cash_addr_obj, &JsValue::from_str("scriptHash"))
                        .map_err(|_| {
                            AddressError::InvalidAddress(
                                "Failed to read cashAddr.scriptHash".to_string(),
                            )
                        })?
                        .as_f64()
                        .ok_or_else(|| {
                            AddressError::InvalidAddress(
                                "cashAddr.scriptHash must be a number".to_string(),
                            )
                        })? as u32;

                Some(CashAddr {
                    prefix,
                    pub_key_hash,
                    script_hash,
                })
            }
        };

        Ok(Network {
            pub_key_hash,
            script_hash,
            cash_addr,
            bech32,
        })
    }
}

/// Convert output script to address string using a utxolib Network object
pub fn from_output_script_with_network(script: &Script, network: &Network) -> Result<String> {
    // Determine script type and choose appropriate codec
    // Note: We always use base58check for P2PKH/P2SH to match utxolib behavior,
    // even if cashAddr is available. Cashaddr is only used for decoding.
    if script.is_p2pkh() || script.is_p2sh() {
        let codec = Base58CheckCodec::new(network.pub_key_hash, network.script_hash);
        use crate::address::AddressCodec;
        codec.encode(script)
    } else if script.is_p2wpkh() || script.is_p2wsh() || script.is_p2tr() {
        // For witness scripts, use bech32 if available
        if let Some(ref hrp) = network.bech32 {
            let (witness_version, program) = bech32::extract_witness_program(script)?;
            bech32::encode_witness_with_custom_hrp(program, witness_version, hrp)
        } else {
            Err(AddressError::UnsupportedScriptType(
                "Network does not support bech32 addresses".to_string(),
            ))
        }
    } else {
        Err(AddressError::UnsupportedScriptType(format!(
            "Unsupported script type for address encoding, length: {}",
            script.len()
        )))
    }
}

/// Convert address string to output script using a utxolib Network object
pub fn to_output_script_with_network(address: &str, network: &Network) -> Result<ScriptBuf> {
    use crate::address::AddressCodec;
    use crate::bitcoin::hashes::Hash;
    use crate::bitcoin::{PubkeyHash, ScriptHash};

    // Try base58check first (always available)
    let base58_codec = Base58CheckCodec::new(network.pub_key_hash, network.script_hash);
    if let Ok(script) = base58_codec.decode(address) {
        return Ok(script);
    }

    // Try bech32 if available
    if let Some(ref hrp) = network.bech32 {
        if let Ok(script_bytes) = bech32::decode_witness_with_custom_hrp(address, hrp) {
            return Ok(ScriptBuf::from_bytes(script_bytes));
        }
    }

    // Try cashaddr if available
    if let Some(ref cash_addr) = network.cash_addr {
        if let Ok((hash, is_p2sh)) = cashaddr::decode_cashaddr(address, &cash_addr.prefix) {
            let hash_array: [u8; 20] = hash
                .try_into()
                .map_err(|_| AddressError::CashaddrError("Invalid hash length".to_string()))?;

            return if is_p2sh {
                let script_hash = ScriptHash::from_byte_array(hash_array);
                Ok(ScriptBuf::new_p2sh(&script_hash))
            } else {
                let pubkey_hash = PubkeyHash::from_byte_array(hash_array);
                Ok(ScriptBuf::new_p2pkh(&pubkey_hash))
            };
        }
    }

    Err(AddressError::InvalidAddress(format!(
        "Could not decode address with any available codec: {}",
        address
    )))
}

// WASM bindings for utxolib-compatible address functions
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Address;

#[wasm_bindgen]
impl Address {
    /// Convert output script to address string
    ///
    /// # Arguments
    /// * `script` - The output script as a byte array
    /// * `network` - The utxolib Network object from JavaScript
    #[wasm_bindgen(js_name = fromOutputScript)]
    pub fn from_output_script_js(
        script: &[u8],
        network: JsValue,
    ) -> std::result::Result<String, JsValue> {
        let network =
            Network::from_js_value(&network).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let script_obj = Script::from_bytes(script);

        from_output_script_with_network(script_obj, &network)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Convert address string to output script
    ///
    /// # Arguments
    /// * `address` - The address string
    /// * `network` - The utxolib Network object from JavaScript
    #[wasm_bindgen(js_name = toOutputScript)]
    pub fn to_output_script_js(
        address: &str,
        network: JsValue,
    ) -> std::result::Result<Vec<u8>, JsValue> {
        let network =
            Network::from_js_value(&network).map_err(|e| JsValue::from_str(&e.to_string()))?;

        to_output_script_with_network(address, &network)
            .map(|script| script.to_bytes())
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
