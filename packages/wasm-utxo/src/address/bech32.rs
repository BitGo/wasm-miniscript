//! Bech32 and Bech32m encoding/decoding for Bitcoin witness addresses.
//!
//! Implements BIP 173 (Bech32) and BIP 350 (Bech32m) encoding schemes using the bitcoin crate.
//! - Bech32 is used for witness version 0 (P2WPKH, P2WSH)
//! - Bech32m is used for witness version 1+ (P2TR)

use super::{AddressCodec, AddressError, Result};
use crate::bitcoin::{Script, ScriptBuf, WitnessVersion};

/// Bech32/Bech32m codec for witness addresses
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bech32Codec {
    /// Bech32 Human Readable Part (HRP)
    pub hrp: &'static str,
}

impl Bech32Codec {
    /// Create a new Bech32 codec with the specified HRP
    pub const fn new(hrp: &'static str) -> Self {
        Self { hrp }
    }
}

/// Encode witness program with custom HRP
fn encode_witness_with_custom_hrp(
    program: &[u8],
    version: WitnessVersion,
    hrp_str: &str,
) -> Result<String> {
    // Try using the bech32 functionality from bitcoin crate
    // The bitcoin crate includes bech32 encoding via its dependencies
    use bech32::{self, Hrp};

    // Parse the HRP
    let hrp = Hrp::parse(hrp_str)
        .map_err(|e| AddressError::Bech32Error(format!("Invalid HRP '{}': {}", hrp_str, e)))?;

    // Encode based on witness version
    let address = if version == WitnessVersion::V0 {
        // Use Bech32 for witness version 0
        bech32::segwit::encode_v0(hrp, program)
            .map_err(|e| AddressError::Bech32Error(format!("Bech32 encoding failed: {}", e)))?
    } else {
        // Use Bech32m for witness version 1+
        bech32::segwit::encode_v1(hrp, program)
            .map_err(|e| AddressError::Bech32Error(format!("Bech32m encoding failed: {}", e)))?
    };

    Ok(address)
}

/// Decode witness program with custom HRP
fn decode_witness_with_custom_hrp(address: &str, expected_hrp: &str) -> Result<Vec<u8>> {
    use bech32::{self, Hrp};

    // Parse the expected HRP
    let expected_hrp_parsed = Hrp::parse(expected_hrp)
        .map_err(|e| AddressError::Bech32Error(format!("Invalid HRP '{}': {}", expected_hrp, e)))?;

    // Decode the address
    let (decoded_hrp, witness_version, witness_program) = bech32::segwit::decode(address)
        .map_err(|e| AddressError::Bech32Error(format!("Failed to decode address: {}", e)))?;

    // Verify HRP matches
    if decoded_hrp != expected_hrp_parsed {
        return Err(AddressError::Bech32Error(format!(
            "HRP mismatch: expected '{}', got '{}'",
            expected_hrp, decoded_hrp
        )));
    }

    // Convert witness version (Fe32) to OP code
    // Fe32 can be 0-31, but for segwit, we only care about 0-16
    // OP_0 = 0x00, OP_1 = 0x51, OP_2 = 0x52, ... OP_16 = 0x60
    let version_byte: u8 = witness_version.to_u8();
    let version_opcode = if version_byte == 0 {
        0x00 // OP_0
    } else if version_byte <= 16 {
        0x50 + version_byte // OP_1 through OP_16
    } else {
        return Err(AddressError::Bech32Error(format!(
            "Invalid witness version: {}",
            version_byte
        )));
    };

    // Construct the script pubkey: <version> <length> <program>
    let mut script = vec![version_opcode, witness_program.len() as u8];
    script.extend_from_slice(&witness_program);
    Ok(script)
}

impl AddressCodec for Bech32Codec {
    fn encode(&self, script: &Script) -> Result<String> {
        let (witness_version, program) = if script.is_p2wpkh() {
            if script.len() != 22 {
                return Err(AddressError::InvalidScript(
                    "Invalid P2WPKH script length".to_string(),
                ));
            }
            (WitnessVersion::V0, &script.as_bytes()[2..22])
        } else if script.is_p2wsh() {
            if script.len() != 34 {
                return Err(AddressError::InvalidScript(
                    "Invalid P2WSH script length".to_string(),
                ));
            }
            (WitnessVersion::V0, &script.as_bytes()[2..34])
        } else if script.is_p2tr() {
            if script.len() != 34 {
                return Err(AddressError::InvalidScript(
                    "Invalid P2TR script length".to_string(),
                ));
            }
            (WitnessVersion::V1, &script.as_bytes()[2..34])
        } else {
            return Err(AddressError::UnsupportedScriptType(
                "Bech32 only supports witness programs (P2WPKH, P2WSH, P2TR)".to_string(),
            ));
        };

        // Use custom HRP encoding for all networks
        encode_witness_with_custom_hrp(program, witness_version, self.hrp)
    }

    fn decode(&self, address: &str) -> Result<ScriptBuf> {
        // Use custom HRP decoding for all networks
        let script_bytes = decode_witness_with_custom_hrp(address, self.hrp)?;
        Ok(ScriptBuf::from(script_bytes))
    }
}
