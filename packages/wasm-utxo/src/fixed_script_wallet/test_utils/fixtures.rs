//! Fixture parsing utilities for fixed script wallet tests
//!
//! This module provides utilities for parsing JSON fixture files containing PSBT test data.
//!
//! # Example Usage
//!
//! ```rust,no_run
//! use wasm_miniscript::fixed_script_wallet::test_utils::fixtures::*;
//!
//! // Load a fixture by network and signature state
//! let fixture = load_psbt_fixture("bitcoin", SignatureState::Fullsigned)
//!     .expect("Failed to load fixture");
//!
//! // Parse the PSBT from base64
//! let psbt = decode_psbt_from_fixture(&fixture)
//!     .expect("Failed to decode PSBT");
//!
//! // Parse wallet keys (xprv)
//! let xprvs = parse_wallet_keys(&fixture)
//!     .expect("Failed to parse wallet keys");
//!
//! // Access fixture data
//! assert_eq!(fixture.wallet_keys.len(), 3);
//! assert_eq!(fixture.inputs.len(), 7);
//! assert_eq!(fixture.psbt_inputs.len(), 7);
//! assert_eq!(fixture.outputs.len(), 5);
//! assert_eq!(fixture.psbt_outputs.len(), 5);
//!
//! // Check input types
//! match &fixture.psbt_inputs[0] {
//!     PsbtInputFixture::P2sh(input) => {
//!         println!("P2SH input with {} derivations", input.bip32_derivation.len());
//!     }
//!     PsbtInputFixture::P2trLegacy(input) => {
//!         println!("P2TR input with {} tap leaf scripts", input.tap_leaf_script.len());
//!     }
//!     _ => {}
//! }
//! ```

use serde::{Deserialize, Serialize};

// Basic helper types (no dependencies on other types in this file)

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnknownKeyVal {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TxInput {
    pub hash: String,
    pub index: u32,
    pub sequence: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TxOutput {
    pub script: String,
    pub value: String,
    pub address: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessUtxo {
    pub script: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Bip32Derivation {
    pub pubkey: String,
    pub path: String,
    pub master_fingerprint: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PartialSig {
    pub pubkey: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TapLeafScript {
    pub control_block: String,
    pub script: String,
    pub leaf_version: u8,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TapBip32Derivation {
    pub leaf_hashes: Vec<String>,
    pub pubkey: String,
    pub path: String,
    pub master_fingerprint: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TapScriptSig {
    pub pubkey: String,
    pub signature: String,
    pub leaf_hash: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TapTreeLeaf {
    pub script: String,
    pub leaf_version: u8,
    pub depth: u8,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TapTree {
    pub leaves: Vec<TapTreeLeaf>,
}

// Input type structs (depend on helper types above)

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct P2shInput {
    pub unknown_key_vals: Vec<UnknownKeyVal>,
    pub non_witness_utxo: String,
    pub sighash_type: u32,
    pub bip32_derivation: Vec<Bip32Derivation>,
    pub redeem_script: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub partial_sig: Vec<PartialSig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct P2shP2wshInput {
    pub unknown_key_vals: Vec<UnknownKeyVal>,
    pub witness_utxo: WitnessUtxo,
    pub sighash_type: u32,
    pub bip32_derivation: Vec<Bip32Derivation>,
    pub witness_script: String,
    pub redeem_script: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub partial_sig: Vec<PartialSig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct P2wshInput {
    pub unknown_key_vals: Vec<UnknownKeyVal>,
    pub witness_utxo: WitnessUtxo,
    pub sighash_type: u32,
    pub bip32_derivation: Vec<Bip32Derivation>,
    pub witness_script: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub partial_sig: Vec<PartialSig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct P2trScriptPathInput {
    pub unknown_key_vals: Vec<UnknownKeyVal>,
    pub witness_utxo: WitnessUtxo,
    pub sighash_type: u32,
    pub tap_leaf_script: Vec<TapLeafScript>,
    pub tap_bip32_derivation: Vec<TapBip32Derivation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tap_script_sig: Vec<TapScriptSig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct P2trMusig2KeyPathInput {
    pub unknown_key_vals: Vec<UnknownKeyVal>,
    pub witness_utxo: WitnessUtxo,
    pub sighash_type: u32,
    pub tap_internal_key: String,
    pub tap_merkle_root: String,
    pub tap_bip32_derivation: Vec<TapBip32Derivation>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct P2shP2pkInput {
    pub unknown_key_vals: Vec<UnknownKeyVal>,
    pub redeem_script: String,
    pub non_witness_utxo: String,
    pub sighash_type: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub partial_sig: Vec<PartialSig>,
}

// Input enum (depends on input type structs)

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum PsbtInputFixture {
    #[serde(rename = "p2sh")]
    P2sh(P2shInput),
    #[serde(rename = "p2shP2wsh")]
    P2shP2wsh(P2shP2wshInput),
    #[serde(rename = "p2wsh")]
    P2wsh(P2wshInput),
    #[serde(rename = "p2tr")]
    P2trLegacy(P2trScriptPathInput),
    #[serde(rename = "p2trMusig2")]
    P2trMusig2ScriptPath(P2trScriptPathInput),
    #[serde(rename = "taprootKeyPathSpend")]
    P2trMusig2KeyPath(P2trMusig2KeyPathInput),
    #[serde(rename = "p2shP2pk")]
    P2shP2pk(P2shP2pkInput),
}

// Output types (depend on helper types)

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PsbtOutputFixture {
    pub unknown_key_vals: Vec<UnknownKeyVal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bip32_derivation: Option<Vec<Bip32Derivation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redeem_script: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_script: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tap_tree: Option<TapTree>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tap_internal_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tap_bip32_derivation: Option<Vec<TapBip32Derivation>>,
}

// Top-level fixture type (depends on input and output types)

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PsbtFixture {
    pub wallet_keys: Vec<String>,
    pub psbt_base64: String,
    pub inputs: Vec<TxInput>,
    pub psbt_inputs: Vec<PsbtInputFixture>,
    pub outputs: Vec<TxOutput>,
    pub psbt_outputs: Vec<PsbtOutputFixture>,
}

// Output script fixture types

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlBlockEntry {
    pub redeem_index: u32,
    pub control_block: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputScriptFixture {
    pub script_type: String,
    pub pubkeys: Vec<String>,
    pub internal_pubkey: String,
    pub control_blocks: Vec<ControlBlockEntry>,
    pub tap_tree: TapTree,
    pub taptree_root: String,
    pub output: String,
}

// Functions (depend on types above)

/// Load a fixture file from the test/fixtures directory and return its contents as a String
///
/// # Arguments
/// * `path` - Path relative to test/fixtures/ (e.g., "fixed-script/psbt.bitcoin.fullsigned.json")
///
/// # Example
/// ```rust,no_run
/// use wasm_miniscript::fixed_script_wallet::test_utils::fixtures::*;
///
/// let contents = load_fixture("fixed-script/psbt.bitcoin.fullsigned.json")
///     .expect("Failed to load fixture");
/// ```
pub fn load_fixture(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let full_path = format!("{}/test/fixtures/{}", env!("CARGO_MANIFEST_DIR"), path);
    let contents = std::fs::read_to_string(&full_path)?;
    Ok(contents)
}

/// Signature state for PSBT fixtures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureState {
    Unsigned,
    Halfsigned,
    Fullsigned,
}

impl SignatureState {
    fn as_str(&self) -> &'static str {
        match self {
            SignatureState::Unsigned => "unsigned",
            SignatureState::Halfsigned => "halfsigned",
            SignatureState::Fullsigned => "fullsigned",
        }
    }
}

/// Load a PSBT fixture from a JSON file
///
/// # Arguments
/// * `network_name` - The network name (e.g., "bitcoin", "litecoin", "dogecoin")
/// * `signature_state` - The signature state of the PSBT
///
/// # Example
/// ```rust,no_run
/// use wasm_miniscript::fixed_script_wallet::test_utils::fixtures::*;
///
/// let fixture = load_psbt_fixture("bitcoin", SignatureState::Fullsigned)
///     .expect("Failed to load fixture");
/// ```
pub fn load_psbt_fixture(
    network_name: &str,
    signature_state: SignatureState,
) -> Result<PsbtFixture, Box<dyn std::error::Error>> {
    let filename = format!("psbt.{}.{}.json", network_name, signature_state.as_str());
    let path = format!("fixed-script/{}", filename);
    let contents = load_fixture(&path)?;
    let fixture: PsbtFixture = serde_json::from_str(&contents)?;
    Ok(fixture)
}

/// Load a PSBT fixture from JSON string
pub(crate) fn parse_psbt_fixture_json(
    json: &str,
) -> Result<PsbtFixture, Box<dyn std::error::Error>> {
    let fixture: PsbtFixture = serde_json::from_str(json)?;
    Ok(fixture)
}

/// Load output script fixtures for P2TR or P2TR-MuSig2 scripts
///
/// # Arguments
/// * `script_type` - The script type ("p2tr" or "p2trMusig2")
///
/// # Example
/// ```rust,no_run
/// use wasm_miniscript::fixed_script_wallet::test_utils::fixtures::*;
///
/// let fixtures = load_fixture_p2tr_output_scripts("p2tr")
///     .expect("Failed to load p2tr fixtures");
/// ```
pub fn load_fixture_p2tr_output_scripts(
    script_type: &str,
) -> Result<Vec<OutputScriptFixture>, Box<dyn std::error::Error>> {
    let path = format!("fixed-script/output-scripts/{}.json", script_type);
    let contents = load_fixture(&path)?;
    let fixtures: Vec<OutputScriptFixture> = serde_json::from_str(&contents)?;
    Ok(fixtures)
}

/// Decode the PSBT from base64
pub fn decode_psbt_from_fixture(
    fixture: &PsbtFixture,
) -> Result<crate::bitcoin::psbt::Psbt, Box<dyn std::error::Error>> {
    use base64::Engine;

    let psbt_bytes = base64::prelude::BASE64_STANDARD.decode(&fixture.psbt_base64)?;
    let psbt = crate::bitcoin::psbt::Psbt::deserialize(&psbt_bytes)?;
    Ok(psbt)
}

/// Parse wallet keys from fixture (xprv strings)
pub fn parse_wallet_keys(
    fixture: &PsbtFixture,
) -> Result<Vec<crate::bitcoin::bip32::Xpriv>, Box<dyn std::error::Error>> {
    use std::str::FromStr;

    fixture
        .wallet_keys
        .iter()
        .map(|key_str| crate::bitcoin::bip32::Xpriv::from_str(key_str).map_err(|e| e.into()))
        .collect()
}

// Helper functions for validation

/// Compares a generated hex string with an expected hex string
fn assert_hex_eq(generated: &str, expected: &str, field_name: &str) -> Result<(), String> {
    if generated != expected {
        Err(format!(
            "{} mismatch\nExpected: {}\nGot: {}",
            field_name, expected, generated
        ))
    } else {
        Ok(())
    }
}

/// Validates sighash type (should be 0 or 1)
fn validate_sighash_type(sighash_type: u32) -> Result<(), String> {
    if sighash_type != 0 && sighash_type != 1 {
        Err(format!("Unexpected sighash type: {}", sighash_type))
    } else {
        Ok(())
    }
}

/// Validates output script from witness UTXO against generated script
fn validate_witness_output_script(
    witness_utxo_script: &str,
    generated_script: &str,
) -> Result<(), String> {
    assert_hex_eq(generated_script, witness_utxo_script, "Output script")
}

/// Common validation for P2TR variants that includes output script and delegates to spend_info validation
fn validate_p2tr_wallet_scripts<F>(
    witness_utxo_script: &str,
    scripts: &crate::fixed_script_wallet::wallet_scripts::ScriptP2tr,
    validate_spend_info: F,
) -> Result<(), String>
where
    F: FnOnce(&crate::bitcoin::taproot::TaprootSpendInfo) -> Result<(), String>,
{
    validate_witness_output_script(
        witness_utxo_script,
        &scripts.output_script().to_hex_string(),
    )?;
    validate_spend_info(&scripts.spend_info)
}

// Implementation methods for validation

impl P2shInput {
    /// Validates that the generated WalletScripts matches this fixture
    pub fn assert_matches_wallet_scripts(
        &self,
        scripts: &crate::fixed_script_wallet::wallet_scripts::ScriptP2sh,
        output_script: &str,
    ) -> Result<(), String> {
        // Compare output script
        let generated_output = scripts.redeem_script.to_p2sh().to_hex_string();
        assert_hex_eq(&generated_output, output_script, "Output script")?;

        // Compare redeem script
        let redeem_script_hex = scripts.redeem_script.to_hex_string();
        assert_hex_eq(&redeem_script_hex, &self.redeem_script, "Redeem script")?;

        validate_sighash_type(self.sighash_type)
    }
}

impl P2shP2wshInput {
    /// Validates that the generated WalletScripts matches this fixture
    pub fn assert_matches_wallet_scripts(
        &self,
        scripts: &crate::fixed_script_wallet::wallet_scripts::ScriptP2shP2wsh,
        output_script: &str,
    ) -> Result<(), String> {
        // Compare output script
        let generated_output = scripts.redeem_script.to_p2sh().to_hex_string();
        assert_hex_eq(&generated_output, output_script, "Output script")?;

        // Compare redeem script
        let redeem_script_hex = scripts.redeem_script.to_hex_string();
        assert_hex_eq(&redeem_script_hex, &self.redeem_script, "Redeem script")?;

        // Compare witness script
        let witness_script_hex = scripts.witness_script.to_hex_string();
        assert_hex_eq(&witness_script_hex, &self.witness_script, "Witness script")?;

        validate_sighash_type(self.sighash_type)
    }
}

impl P2wshInput {
    /// Validates that the generated WalletScripts matches this fixture
    pub fn assert_matches_wallet_scripts(
        &self,
        scripts: &crate::fixed_script_wallet::wallet_scripts::ScriptP2wsh,
        output_script: &str,
    ) -> Result<(), String> {
        // Compare output script
        let generated_output = scripts.witness_script.to_p2wsh().to_hex_string();
        assert_hex_eq(&generated_output, output_script, "Output script")?;

        // Compare witness script
        let witness_script_hex = scripts.witness_script.to_hex_string();
        assert_hex_eq(&witness_script_hex, &self.witness_script, "Witness script")?;

        validate_sighash_type(self.sighash_type)
    }
}

impl P2trScriptPathInput {
    /// Validates that the generated TaprootSpendInfo matches this fixture
    pub fn assert_matches_spend_info(
        &self,
        spend_info: &crate::bitcoin::taproot::TaprootSpendInfo,
    ) -> Result<(), String> {
        use crate::bitcoin::hashes::hex::FromHex;
        use crate::bitcoin::ScriptBuf;

        // Compare tap leaf scripts and control blocks
        for fixture_leaf in &self.tap_leaf_script {
            let script_bytes = Vec::<u8>::from_hex(&fixture_leaf.script)
                .map_err(|e| format!("Failed to decode leaf script hex: {}", e))?;
            let script = ScriptBuf::from_bytes(script_bytes);

            let control_block = spend_info
                .control_block(&(
                    script.clone(),
                    crate::bitcoin::taproot::LeafVersion::TapScript,
                ))
                .ok_or_else(|| {
                    format!(
                        "Failed to generate control block for script: {}",
                        fixture_leaf.script
                    )
                })?;

            let control_block_hex = hex::encode(control_block.serialize());
            assert_hex_eq(
                &control_block_hex,
                &fixture_leaf.control_block,
                &format!("Control block for script {}", fixture_leaf.script),
            )?;

            if fixture_leaf.leaf_version != 0xc0 {
                return Err(format!(
                    "Expected leaf version 0xc0, got: {}",
                    fixture_leaf.leaf_version
                ));
            }
        }

        validate_sighash_type(self.sighash_type)
    }

    /// Validates that the generated WalletScripts matches this fixture
    /// This is a higher-level method that includes output script validation
    pub fn assert_matches_wallet_scripts(
        &self,
        scripts: &crate::fixed_script_wallet::wallet_scripts::ScriptP2tr,
    ) -> Result<(), String> {
        validate_p2tr_wallet_scripts(&self.witness_utxo.script, scripts, |spend_info| {
            self.assert_matches_spend_info(spend_info)
        })
    }
}

impl P2trMusig2KeyPathInput {
    /// Validates that the generated TaprootSpendInfo matches this fixture
    pub fn assert_matches_spend_info(
        &self,
        spend_info: &crate::bitcoin::taproot::TaprootSpendInfo,
    ) -> Result<(), String> {
        // Compare internal key
        let internal_key_hex = hex::encode(spend_info.internal_key().serialize());
        assert_hex_eq(&internal_key_hex, &self.tap_internal_key, "Internal key")?;

        // Compare merkle root
        let merkle_root = spend_info
            .merkle_root()
            .ok_or_else(|| "Expected merkle root to exist".to_string())?;
        let merkle_root_bytes: &[u8] = merkle_root.as_ref();
        let merkle_root_hex = hex::encode(merkle_root_bytes);
        assert_hex_eq(&merkle_root_hex, &self.tap_merkle_root, "Merkle root")?;

        validate_sighash_type(self.sighash_type)
    }

    /// Validates that the generated WalletScripts matches this fixture
    /// This is a higher-level method that includes output script validation
    pub fn assert_matches_wallet_scripts(
        &self,
        scripts: &crate::fixed_script_wallet::wallet_scripts::ScriptP2tr,
    ) -> Result<(), String> {
        validate_p2tr_wallet_scripts(&self.witness_utxo.script, scripts, |spend_info| {
            self.assert_matches_spend_info(spend_info)
        })
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_fixture_helper() {
        // Test loading a fixture file
        let contents = load_fixture("fixed-script/psbt.bitcoin.fullsigned.json")
            .expect("Failed to load fixture");
        assert!(!contents.is_empty());
        assert!(contents.contains("walletKeys"));
        assert!(contents.contains("psbtBase64"));
    }

    #[test]
    fn test_parse_fixture() {
        let json = r#"{
            "walletKeys": ["xprv..."],
            "psbtBase64": "cHNidP8BAP3q...",
            "inputs": [],
            "psbtInputs": [],
            "outputs": [],
            "psbtOutputs": []
        }"#;

        let result = parse_psbt_fixture_json(json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_bitcoin_fullsigned_fixture() {
        // Example of loading a fixture file
        let fixture = load_psbt_fixture("bitcoin", SignatureState::Fullsigned)
            .expect("Failed to load fixture");

        // Verify structure
        assert_eq!(fixture.wallet_keys.len(), 3);
        assert!(!fixture.psbt_base64.is_empty());
        assert_eq!(fixture.inputs.len(), 7);
        assert_eq!(fixture.psbt_inputs.len(), 7);
        assert_eq!(fixture.outputs.len(), 5);
        assert_eq!(fixture.psbt_outputs.len(), 5);

        // Decode PSBT
        let psbt = decode_psbt_from_fixture(&fixture).expect("Failed to decode PSBT");
        assert_eq!(psbt.inputs.len(), 7);
        assert_eq!(psbt.outputs.len(), 5);

        // Parse wallet keys
        let xprvs = parse_wallet_keys(&fixture).expect("Failed to parse wallet keys");
        assert_eq!(xprvs.len(), 3);
    }

    #[test]
    fn test_load_different_signature_states() {
        // Test unsigned
        let unsigned = load_psbt_fixture("bitcoin", SignatureState::Unsigned)
            .expect("Failed to load unsigned fixture");
        assert_eq!(unsigned.inputs.len(), 7);
        assert_eq!(unsigned.psbt_inputs.len(), 7);

        // Test halfsigned
        let halfsigned = load_psbt_fixture("bitcoin", SignatureState::Halfsigned)
            .expect("Failed to load halfsigned fixture");
        assert_eq!(halfsigned.inputs.len(), 7);
        assert_eq!(halfsigned.psbt_inputs.len(), 7);

        // Test fullsigned
        let fullsigned = load_psbt_fixture("bitcoin", SignatureState::Fullsigned)
            .expect("Failed to load fullsigned fixture");
        assert_eq!(fullsigned.inputs.len(), 7);
        assert_eq!(fullsigned.psbt_inputs.len(), 7);
    }

    #[test]
    fn test_load_different_networks() {
        // Test various networks
        for network in &[
            "bitcoin",
            "litecoin",
            "dogecoin",
            "bitcoincash",
            "ecash",
            "dash",
            "bitcoingold",
        ] {
            let fixture = load_psbt_fixture(network, SignatureState::Fullsigned)
                .unwrap_or_else(|_| panic!("Failed to load {} fixture", network));
            assert_eq!(fixture.wallet_keys.len(), 3);
        }
    }

    #[test]
    fn test_load_p2tr_output_scripts() {
        // Test p2tr
        let p2tr_fixtures =
            load_fixture_p2tr_output_scripts("p2tr").expect("Failed to load p2tr output scripts");
        assert_eq!(p2tr_fixtures.len(), 2);
        assert_eq!(p2tr_fixtures[0].script_type, "p2tr");
        assert_eq!(p2tr_fixtures[0].pubkeys.len(), 3);
        assert_eq!(p2tr_fixtures[0].control_blocks.len(), 3);
        assert_eq!(p2tr_fixtures[0].tap_tree.leaves.len(), 3);

        // Test p2trMusig2
        let p2tr_musig2_fixtures = load_fixture_p2tr_output_scripts("p2trMusig2")
            .expect("Failed to load p2trMusig2 output scripts");
        assert_eq!(p2tr_musig2_fixtures.len(), 2);
        assert_eq!(p2tr_musig2_fixtures[0].script_type, "p2trMusig2");
        assert_eq!(p2tr_musig2_fixtures[0].pubkeys.len(), 3);
        assert_eq!(p2tr_musig2_fixtures[0].control_blocks.len(), 2);
        assert_eq!(p2tr_musig2_fixtures[0].tap_tree.leaves.len(), 2);
    }
}
