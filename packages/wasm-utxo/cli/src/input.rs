use anyhow::{Context, Result};
use base64::Engine;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

/// Decode input bytes, attempting to interpret as base64, hex, or raw bytes
pub fn decode_input(raw_bytes: &[u8]) -> Result<Vec<u8>> {
    // Try to interpret as text first (for base64/hex encoded input)
    if let Ok(text) = std::str::from_utf8(raw_bytes) {
        let trimmed = text.trim();

        // Try hex first (more common format)
        if let Ok(decoded) = hex::decode(trimmed) {
            return Ok(decoded);
        }

        // Try base64
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(trimmed) {
            return Ok(decoded);
        }
    }

    // Fall back to raw bytes
    Ok(raw_bytes.to_vec())
}

/// Read bytes from a file path or stdin (if path is "-")
pub fn read_input_bytes(path: &PathBuf, file_type: &str) -> Result<Vec<u8>> {
    if path.to_str() == Some("-") {
        // Read from stdin
        let mut buffer = Vec::new();
        io::stdin()
            .read_to_end(&mut buffer)
            .context("Failed to read from stdin")?;
        Ok(buffer)
    } else {
        // Read from file
        fs::read(path)
            .with_context(|| format!("Failed to read {} file: {}", file_type, path.display()))
    }
}
