use crate::address::utxolib_compat::{CashAddr, UtxolibNetwork};
use crate::error::WasmMiniscriptError;
use wasm_bindgen::JsValue;

pub(crate) trait TryFromJsValue {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmMiniscriptError>
    where
        Self: Sized;
}

// Implement TryFromJsValue for primitive types

impl TryFromJsValue for String {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmMiniscriptError> {
        value
            .as_string()
            .ok_or_else(|| WasmMiniscriptError::new("Expected a string"))
    }
}

impl TryFromJsValue for u8 {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmMiniscriptError> {
        value
            .as_f64()
            .ok_or_else(|| WasmMiniscriptError::new("Expected a number"))
            .map(|n| n as u8)
    }
}

impl TryFromJsValue for u32 {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmMiniscriptError> {
        value
            .as_f64()
            .ok_or_else(|| WasmMiniscriptError::new("Expected a number"))
            .map(|n| n as u32)
    }
}

impl<T: TryFromJsValue> TryFromJsValue for Option<T> {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmMiniscriptError> {
        if value.is_undefined() || value.is_null() {
            Ok(None)
        } else {
            T::try_from_js_value(value).map(Some)
        }
    }
}

// Helper function to get a field from an object and convert it using TryFromJsValue
pub(crate) fn get_field<T: TryFromJsValue>(
    obj: &JsValue,
    key: &str,
) -> Result<T, WasmMiniscriptError> {
    let field_value = js_sys::Reflect::get(obj, &JsValue::from_str(key))
        .map_err(|_| WasmMiniscriptError::new(&format!("Failed to read {} from object", key)))?;

    T::try_from_js_value(&field_value)
        .map_err(|e| WasmMiniscriptError::new(&format!("{} (field: {})", e, key)))
}

// Helper function to get a nested field using dot notation (e.g., "network.bip32.public")
pub(crate) fn get_nested_field<T: TryFromJsValue>(
    obj: &JsValue,
    path: &str,
) -> Result<T, WasmMiniscriptError> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = obj.clone();

    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            // Last part - extract and convert
            return get_field(&current, part);
        } else {
            // Intermediate part - just get the object
            current = js_sys::Reflect::get(&current, &JsValue::from_str(part)).map_err(|_| {
                WasmMiniscriptError::new(&format!("Failed to read {} from object", part))
            })?;
        }
    }

    Err(WasmMiniscriptError::new("Empty path"))
}

// Helper function to get a buffer field as a fixed-size byte array
pub(crate) fn get_buffer_field<const N: usize>(
    obj: &JsValue,
    key: &str,
) -> Result<[u8; N], WasmMiniscriptError> {
    let field_value = js_sys::Reflect::get(obj, &JsValue::from_str(key))
        .map_err(|_| WasmMiniscriptError::new(&format!("Failed to read {} from object", key)))?;

    let buffer = js_sys::Uint8Array::new(&field_value);
    if buffer.length() as usize != N {
        return Err(WasmMiniscriptError::new(&format!(
            "{} must be {} bytes, got {}",
            key,
            N,
            buffer.length()
        )));
    }

    let mut bytes = [0u8; N];
    buffer.copy_to(&mut bytes);
    Ok(bytes)
}

// Helper function to get a buffer field as a Vec
#[allow(dead_code)]
pub(crate) fn get_buffer_field_vec(
    obj: &JsValue,
    key: &str,
) -> Result<Vec<u8>, WasmMiniscriptError> {
    let field_value = js_sys::Reflect::get(obj, &JsValue::from_str(key))
        .map_err(|_| WasmMiniscriptError::new(&format!("Failed to read {} from object", key)))?;

    let buffer = js_sys::Uint8Array::new(&field_value);
    let mut bytes = vec![0u8; buffer.length() as usize];
    buffer.copy_to(&mut bytes);
    Ok(bytes)
}

impl TryFromJsValue for UtxolibNetwork {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmMiniscriptError> {
        let pub_key_hash = get_field(value, "pubKeyHash")?;
        let script_hash = get_field(value, "scriptHash")?;
        let bech32 = get_field(value, "bech32")?;
        let cash_addr = get_field(value, "cashAddr")?;

        Ok(UtxolibNetwork {
            pub_key_hash,
            script_hash,
            cash_addr,
            bech32,
        })
    }
}

impl TryFromJsValue for CashAddr {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmMiniscriptError> {
        let prefix = get_field(value, "prefix")?;
        let pub_key_hash = get_field(value, "pubKeyHash")?;
        let script_hash = get_field(value, "scriptHash")?;

        Ok(CashAddr {
            prefix,
            pub_key_hash,
            script_hash,
        })
    }
}
