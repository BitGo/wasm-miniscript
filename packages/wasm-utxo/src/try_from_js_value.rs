use crate::address::utxolib_compat::{CashAddr, Network};
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
fn get_field<T: TryFromJsValue>(obj: &JsValue, key: &str) -> Result<T, WasmMiniscriptError> {
    let field_value = js_sys::Reflect::get(obj, &JsValue::from_str(key))
        .map_err(|_| WasmMiniscriptError::new(&format!("Failed to read {} from object", key)))?;

    T::try_from_js_value(&field_value)
        .map_err(|e| WasmMiniscriptError::new(&format!("{} (field: {})", e, key)))
}

impl TryFromJsValue for Network {
    fn try_from_js_value(value: &JsValue) -> Result<Self, WasmMiniscriptError> {
        let pub_key_hash = get_field(value, "pubKeyHash")?;
        let script_hash = get_field(value, "scriptHash")?;
        let bech32 = get_field(value, "bech32")?;
        let cash_addr = get_field(value, "cashAddr")?;

        Ok(Network {
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
