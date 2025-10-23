//! Base58Check encoding/decoding for traditional Bitcoin addresses (P2PKH, P2SH).

use super::{AddressCodec, AddressError, Result};
use crate::bitcoin::hashes::Hash;
use crate::bitcoin::{base58, PubkeyHash, Script, ScriptBuf, ScriptHash};

/// Base58Check codec with network-specific version bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Base58CheckCodec {
    /// Base58Check P2PKH version byte(s)
    pub pub_key_hash: u32,
    /// Base58Check P2SH version byte(s)
    pub script_hash: u32,
}

impl Base58CheckCodec {
    /// Create a new Base58Check codec with specified version bytes
    pub const fn new(pub_key_hash: u32, script_hash: u32) -> Self {
        Self {
            pub_key_hash,
            script_hash,
        }
    }
}

/// Encode a hash with version bytes to Base58Check format using bitcoin crate
fn to_base58_check(hash: &[u8], version: u32) -> Result<String> {
    let mut data = Vec::new();

    // Encode version bytes (1-4 bytes depending on size)
    if version <= 0xff {
        data.push(version as u8);
    } else if version <= 0xffff {
        data.extend_from_slice(&(version as u16).to_be_bytes());
    } else {
        // For Zcash (up to 4 bytes)
        let bytes = version.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(0);
        data.extend_from_slice(&bytes[start..]);
    }

    data.extend_from_slice(hash);

    // Use bitcoin crate's base58 encode_check which adds the checksum
    Ok(base58::encode_check(&data))
}

/// Decode a Base58Check address to (hash, version) using bitcoin crate
fn from_base58_check(address: &str) -> Result<(Vec<u8>, u32)> {
    // Use bitcoin crate's base58 decode_check which verifies the checksum
    let payload =
        base58::decode_check(address).map_err(|e| AddressError::Base58Error(e.to_string()))?;

    if payload.is_empty() {
        return Err(AddressError::Base58Error("Empty payload".to_string()));
    }

    // Extract version and hash
    // Try different version byte lengths
    let (version, hash) = if payload.len() >= 21 && (payload[0] == 0x1c || payload[0] == 0x1d) {
        // Zcash uses 2-byte versions starting with 0x1c or 0x1d
        if payload.len() >= 22 {
            let version = u32::from_be_bytes([0, 0, payload[0], payload[1]]);
            let hash = payload[2..].to_vec();
            (version, hash)
        } else {
            // Single byte version
            let version = payload[0] as u32;
            let hash = payload[1..].to_vec();
            (version, hash)
        }
    } else {
        // Standard single-byte version
        let version = payload[0] as u32;
        let hash = payload[1..].to_vec();
        (version, hash)
    };

    Ok((hash, version))
}

impl AddressCodec for Base58CheckCodec {
    fn encode(&self, script: &Script) -> Result<String> {
        if script.is_p2pkh() {
            if script.len() != 25 {
                return Err(AddressError::InvalidScript(
                    "Invalid P2PKH script length".to_string(),
                ));
            }
            let hash = &script.as_bytes()[3..23];
            to_base58_check(hash, self.pub_key_hash)
        } else if script.is_p2sh() {
            if script.len() != 23 {
                return Err(AddressError::InvalidScript(
                    "Invalid P2SH script length".to_string(),
                ));
            }
            let hash = &script.as_bytes()[2..22];
            to_base58_check(hash, self.script_hash)
        } else {
            Err(AddressError::UnsupportedScriptType(
                "Base58Check only supports P2PKH and P2SH".to_string(),
            ))
        }
    }

    fn decode(&self, address: &str) -> Result<ScriptBuf> {
        let (hash, version) = from_base58_check(address)?;

        if version == self.pub_key_hash {
            let hash_array: [u8; 20] = hash.try_into().map_err(|_| {
                AddressError::InvalidAddress("Invalid pubkey hash length".to_string())
            })?;
            let pubkey_hash = PubkeyHash::from_byte_array(hash_array);
            Ok(ScriptBuf::new_p2pkh(&pubkey_hash))
        } else if version == self.script_hash {
            let hash_array: [u8; 20] = hash.try_into().map_err(|_| {
                AddressError::InvalidAddress("Invalid script hash length".to_string())
            })?;
            let script_hash = ScriptHash::from_byte_array(hash_array);
            Ok(ScriptBuf::new_p2sh(&script_hash))
        } else {
            Err(AddressError::InvalidAddress(format!(
                "Version mismatch: expected {} or {}, got {}",
                self.pub_key_hash, self.script_hash, version
            )))
        }
    }
}
