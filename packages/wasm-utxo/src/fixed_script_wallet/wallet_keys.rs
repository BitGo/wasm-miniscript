use std::convert::TryInto;
use std::str::FromStr;

use crate::bitcoin::bip32::{ChildNumber, DerivationPath};
use crate::bitcoin::{bip32::Xpub, secp256k1::Secp256k1, CompressedPublicKey};
use crate::error::WasmUtxoError;

pub type XpubTriple = [Xpub; 3];

pub type PubTriple = [CompressedPublicKey; 3];

pub fn xpub_triple_from_strings(xpub_strings: &[String; 3]) -> Result<XpubTriple, WasmUtxoError> {
    let xpubs: Result<Vec<Xpub>, _> = xpub_strings
        .iter()
        .map(|s| {
            Xpub::from_str(s)
                .map_err(|e| WasmUtxoError::new(&format!("Failed to parse xpub: {}", e)))
        })
        .collect();

    xpubs?
        .try_into()
        .map_err(|_| WasmUtxoError::new("Expected exactly 3 xpubs"))
}

pub fn to_pub_triple(xpubs: &XpubTriple) -> PubTriple {
    xpubs
        .iter()
        .map(|x| x.to_pub())
        .collect::<Vec<_>>()
        .try_into()
        .expect("could not convert vec to array")
}

#[derive(Debug)]
pub struct RootWalletKeys {
    xpubs: XpubTriple,
    derivation_prefixes: [DerivationPath; 3],
}

impl RootWalletKeys {
    pub fn new_with_derivation_prefixes(
        xpubs: XpubTriple,
        derivation_prefixes: [DerivationPath; 3],
    ) -> Self {
        Self {
            xpubs,
            derivation_prefixes,
        }
    }

    pub fn new(xpubs: XpubTriple) -> Self {
        Self::new_with_derivation_prefixes(
            xpubs,
            [
                DerivationPath::from_str("m/0/0").unwrap(),
                DerivationPath::from_str("m/0/0").unwrap(),
                DerivationPath::from_str("m/0/0").unwrap(),
            ],
        )
    }

    pub fn derive_for_chain_and_index(
        &self,
        chain: u32,
        index: u32,
    ) -> Result<XpubTriple, WasmUtxoError> {
        let paths: Vec<DerivationPath> = self
            .derivation_prefixes
            .iter()
            .map(|p| {
                p.child(ChildNumber::Normal { index: chain })
                    .child(ChildNumber::Normal { index })
            })
            .collect::<Vec<_>>();

        let ctx = Secp256k1::new();

        // zip xpubs and paths, and return a Result<XpubTriple, WasmUtxoError>
        self.xpubs
            .iter()
            .zip(paths.iter())
            .map(|(x, p)| {
                x.derive_pub(&ctx, p)
                    .map_err(|e| WasmUtxoError::new(&format!("Error deriving xpub: {}", e)))
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| WasmUtxoError::new("Expected exactly 3 derived xpubs"))
    }
}

#[cfg(test)]
pub mod tests {
    use crate::bitcoin::bip32::{Xpriv, Xpub};
    use crate::bitcoin::hashes::{sha256, Hash};
    use crate::fixed_script_wallet::RootWalletKeys;

    pub type XprivTriple = [Xpriv; 3];

    pub fn get_xpriv_from_seed(seed: &str) -> Xpriv {
        use crate::bitcoin::bip32::Xpriv;
        use crate::bitcoin::Network;

        // hash seed into 32 bytes
        let seed_hash = sha256::Hash::hash(seed.as_bytes()).to_byte_array();

        Xpriv::new_master(Network::Testnet, &seed_hash).expect("could not create xpriv from seed")
    }

    pub fn get_test_wallet_xprvs(seed: &str) -> XprivTriple {
        let a = get_xpriv_from_seed(&format!("{}/0", seed));
        let b = get_xpriv_from_seed(&format!("{}/1", seed));
        let c = get_xpriv_from_seed(&format!("{}/2", seed));
        [a, b, c]
    }

    pub fn get_test_wallet_keys(seed: &str) -> RootWalletKeys {
        let xprvs = get_test_wallet_xprvs(seed);
        let secp = crate::bitcoin::key::Secp256k1::new();
        RootWalletKeys::new(xprvs.map(|x| Xpub::from_priv(&secp, &x)))
    }

    #[test]
    fn it_works() {
        let keys = get_test_wallet_keys("test");
        assert!(keys.derive_for_chain_and_index(0, 0).is_ok());
    }
}

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
pub mod wasm_tests {
    use super::tests::get_test_wallet_xprvs;
    use crate::bitcoin::bip32::Xpub;
    use crate::wasm::wallet_keys_helpers::root_wallet_keys_from_jsvalue;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_from_jsvalue_valid_keys_wasm() {
        // Get test xpubs as strings
        let xpubs = get_test_wallet_xprvs("test");
        let secp = crate::bitcoin::key::Secp256k1::new();
        let xpub_strings: Vec<String> = xpubs
            .iter()
            .map(|xprv| Xpub::from_priv(&secp, xprv).to_string())
            .collect();

        // Create a JS array with the xpub strings
        let js_array = js_sys::Array::new();
        for xpub_str in xpub_strings.iter() {
            js_array.push(&JsValue::from_str(xpub_str));
        }

        // Test from_jsvalue with actual JsValue
        let result = root_wallet_keys_from_jsvalue(&js_array.into());
        assert!(result.is_ok());

        let wallet_keys = result.unwrap();
        // Verify we can derive keys
        assert!(wallet_keys.derive_for_chain_and_index(0, 0).is_ok());
        assert!(wallet_keys.derive_for_chain_and_index(1, 5).is_ok());
    }

    #[wasm_bindgen_test]
    fn test_from_jsvalue_invalid_count_wasm() {
        // Create a JS array with only 2 xpubs (should fail)
        let xpubs = get_test_wallet_xprvs("test");
        let secp = crate::bitcoin::key::Secp256k1::new();

        let js_array = js_sys::Array::new();
        for i in 0..2 {
            let xpub_str = Xpub::from_priv(&secp, &xpubs[i]).to_string();
            js_array.push(&JsValue::from_str(&xpub_str));
        }

        let result = root_wallet_keys_from_jsvalue(&js_array.into());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Expected exactly 3 xpub keys"
        );
    }

    #[wasm_bindgen_test]
    fn test_from_jsvalue_too_many_keys_wasm() {
        // Create a JS array with 4 xpubs (should fail)
        let xpubs = get_test_wallet_xprvs("test");
        let secp = crate::bitcoin::key::Secp256k1::new();

        let js_array = js_sys::Array::new();
        for i in 0..3 {
            let xpub_str = Xpub::from_priv(&secp, &xpubs[i]).to_string();
            js_array.push(&JsValue::from_str(&xpub_str));
        }
        // Add one more
        js_array.push(&JsValue::from_str(
            &Xpub::from_priv(&secp, &xpubs[0]).to_string(),
        ));

        let result = root_wallet_keys_from_jsvalue(&js_array.into());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Expected exactly 3 xpub keys"
        );
    }

    #[wasm_bindgen_test]
    fn test_from_jsvalue_invalid_xpub_wasm() {
        // Create a JS array with 3 values, all of which are not valid xpubs
        let js_array = js_sys::Array::new();
        js_array.push(&JsValue::from_str("not-a-valid-xpub"));
        js_array.push(&JsValue::from_str("also-not-valid"));
        js_array.push(&JsValue::from_str("still-not-valid"));

        let result = root_wallet_keys_from_jsvalue(&js_array.into());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse xpub"));
    }

    #[wasm_bindgen_test]
    fn test_from_jsvalue_non_string_element_wasm() {
        // Create a JS array with a non-string element
        let js_array = js_sys::Array::new();
        js_array.push(&JsValue::from_f64(123.0)); // number instead of string
        js_array.push(&JsValue::from_str("xpub2"));
        js_array.push(&JsValue::from_str("xpub3"));

        let result = root_wallet_keys_from_jsvalue(&js_array.into());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Key at index 0 is not a string"));
    }

    #[wasm_bindgen_test]
    fn test_from_jsvalue_mixed_invalid_wasm() {
        // Create a JS array with mixed invalid values
        let js_array = js_sys::Array::new();
        js_array.push(&JsValue::NULL);
        js_array.push(&JsValue::UNDEFINED);
        js_array.push(&JsValue::from_bool(true));

        let result = root_wallet_keys_from_jsvalue(&js_array.into());
        assert!(result.is_err());
    }
}
