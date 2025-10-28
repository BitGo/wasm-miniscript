use std::convert::TryInto;
use std::str::FromStr;

use crate::bitcoin::bip32::{ChildNumber, DerivationPath};
use crate::bitcoin::{bip32::Xpub, secp256k1::Secp256k1, CompressedPublicKey};
use crate::error::WasmMiniscriptError;
use wasm_bindgen::JsValue;

use super::bip32interface::xpub_from_bip32interface;

pub type XpubTriple = [Xpub; 3];

pub type PubTriple = [CompressedPublicKey; 3];

pub fn xpub_triple_from_jsvalue(keys: &JsValue) -> Result<XpubTriple, WasmMiniscriptError> {
    let keys_array = js_sys::Array::from(keys);
    if keys_array.length() != 3 {
        return Err(WasmMiniscriptError::new("Expected exactly 3 xpub keys"));
    }

    let key_strings: Result<[String; 3], _> = (0..3)
        .map(|i| {
            keys_array.get(i).as_string().ok_or_else(|| {
                WasmMiniscriptError::new(&format!("Key at index {} is not a string", i))
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .and_then(|v| {
            v.try_into()
                .map_err(|_| WasmMiniscriptError::new("Failed to convert to array"))
        });

    xpub_triple_from_strings(&key_strings?)
}

pub fn xpub_triple_from_strings(
    xpub_strings: &[String; 3],
) -> Result<XpubTriple, WasmMiniscriptError> {
    let xpubs: Result<Vec<Xpub>, _> = xpub_strings
        .iter()
        .map(|s| {
            Xpub::from_str(s)
                .map_err(|e| WasmMiniscriptError::new(&format!("Failed to parse xpub: {}", e)))
        })
        .collect();

    xpubs?
        .try_into()
        .map_err(|_| WasmMiniscriptError::new("Expected exactly 3 xpubs"))
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
    ) -> Result<XpubTriple, WasmMiniscriptError> {
        let paths: Vec<DerivationPath> = self
            .derivation_prefixes
            .iter()
            .map(|p| {
                p.child(ChildNumber::Normal { index: chain })
                    .child(ChildNumber::Normal { index })
            })
            .collect::<Vec<_>>();

        let ctx = Secp256k1::new();

        // zip xpubs and paths, and return a Result<XpubTriple, WasmMiniscriptError>
        self.xpubs
            .iter()
            .zip(paths.iter())
            .map(|(x, p)| {
                x.derive_pub(&ctx, p)
                    .map_err(|e| WasmMiniscriptError::new(&format!("Error deriving xpub: {}", e)))
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| WasmMiniscriptError::new("Expected exactly 3 derived xpubs"))
    }

    pub(crate) fn from_jsvalue(keys: &JsValue) -> Result<RootWalletKeys, WasmMiniscriptError> {
        // Check if keys is an array (xpub strings) or an object (WalletKeys/RootWalletKeys)
        if js_sys::Array::is_array(keys) {
            // Handle array of xpub strings
            let xpubs = xpub_triple_from_jsvalue(keys)?;
            Ok(RootWalletKeys::new_with_derivation_prefixes(
                xpubs,
                [
                    DerivationPath::from_str("m/0/0").unwrap(),
                    DerivationPath::from_str("m/0/0").unwrap(),
                    DerivationPath::from_str("m/0/0").unwrap(),
                ],
            ))
        } else if keys.is_object() {
            // Handle WalletKeys/RootWalletKeys object
            let obj = js_sys::Object::from(keys.clone());

            // Get the triple property
            let triple = js_sys::Reflect::get(&obj, &JsValue::from_str("triple"))
                .map_err(|_| WasmMiniscriptError::new("Failed to get 'triple' property"))?;

            if !js_sys::Array::is_array(&triple) {
                return Err(WasmMiniscriptError::new(
                    "'triple' property must be an array",
                ));
            }

            let triple_array = js_sys::Array::from(&triple);
            if triple_array.length() != 3 {
                return Err(WasmMiniscriptError::new(
                    "'triple' must contain exactly 3 keys",
                ));
            }

            // Extract xpubs from BIP32Interface objects
            let xpubs: XpubTriple = (0..3)
                .map(|i| {
                    let bip32_key = triple_array.get(i);
                    xpub_from_bip32interface(&bip32_key)
                })
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| WasmMiniscriptError::new("Failed to convert to array"))?;

            // Try to get derivationPrefixes if present (for RootWalletKeys)
            let derivation_prefixes =
                js_sys::Reflect::get(&obj, &JsValue::from_str("derivationPrefixes"))
                    .ok()
                    .and_then(|prefixes| {
                        if prefixes.is_undefined() || prefixes.is_null() {
                            return None;
                        }

                        if !js_sys::Array::is_array(&prefixes) {
                            return None;
                        }

                        let prefixes_array = js_sys::Array::from(&prefixes);
                        if prefixes_array.length() != 3 {
                            return None;
                        }

                        let prefix_strings: Result<[String; 3], _> = (0..3)
                            .map(|i| {
                                prefixes_array.get(i).as_string().ok_or_else(|| {
                                    WasmMiniscriptError::new("Prefix is not a string")
                                })
                            })
                            .collect::<Result<Vec<_>, _>>()
                            .and_then(|v| {
                                v.try_into().map_err(|_| {
                                    WasmMiniscriptError::new("Failed to convert to array")
                                })
                            });

                        prefix_strings.ok()
                    });

            // Convert prefix strings to DerivationPath
            let derivation_paths = if let Some(prefixes) = derivation_prefixes {
                prefixes
                    .iter()
                    .map(|p| {
                        // Remove leading 'm/' if present and add it back
                        let p = p.strip_prefix("m/").unwrap_or(p);
                        DerivationPath::from_str(&format!("m/{}", p)).map_err(|e| {
                            WasmMiniscriptError::new(&format!("Invalid derivation prefix: {}", e))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .map_err(|_| WasmMiniscriptError::new("Failed to convert derivation paths"))?
            } else {
                [
                    DerivationPath::from_str("m/0/0").unwrap(),
                    DerivationPath::from_str("m/0/0").unwrap(),
                    DerivationPath::from_str("m/0/0").unwrap(),
                ]
            };

            Ok(RootWalletKeys::new_with_derivation_prefixes(
                xpubs,
                derivation_paths,
            ))
        } else {
            Err(WasmMiniscriptError::new(
                "Expected array of xpub strings or WalletKeys object",
            ))
        }
    }
}

#[cfg(test)]
pub mod tests {
    use crate::bitcoin::bip32::{Xpriv, Xpub};
    use crate::bitcoin::hashes::{sha256, Hash};
    use crate::RootWalletKeys;

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
    use crate::RootWalletKeys;
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
        let result = RootWalletKeys::from_jsvalue(&js_array.into());
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

        let result = RootWalletKeys::from_jsvalue(&js_array.into());
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

        let result = RootWalletKeys::from_jsvalue(&js_array.into());
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

        let result = RootWalletKeys::from_jsvalue(&js_array.into());
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

        let result = RootWalletKeys::from_jsvalue(&js_array.into());
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

        let result = RootWalletKeys::from_jsvalue(&js_array.into());
        assert!(result.is_err());
    }
}
