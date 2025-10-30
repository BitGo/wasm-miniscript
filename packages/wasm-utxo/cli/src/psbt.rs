use anyhow::{Context, Result};
use base64::Engine;
use clap::Subcommand;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use crate::format::{render_tree_with_scheme, ColorScheme};
use crate::parse_node::parse_psbt_bytes_internal;

fn decode_input(raw_bytes: &[u8]) -> Result<Vec<u8>> {
    // Try to interpret as text first (for base64/hex encoded input)
    if let Ok(text) = std::str::from_utf8(raw_bytes) {
        let trimmed = text.trim();

        // Try base64 first (more common for PSBTs)
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(trimmed) {
            return Ok(decoded);
        }

        // Try hex
        if let Ok(decoded) = hex::decode(trimmed) {
            return Ok(decoded);
        }
    }

    // Fall back to raw bytes
    Ok(raw_bytes.to_vec())
}

#[derive(Subcommand)]
pub enum PsbtCommand {
    /// Parse a PSBT file and display its contents
    Parse {
        /// Path to the PSBT file (use '-' to read from stdin)
        path: PathBuf,
        /// Disable colored output
        #[arg(long)]
        no_color: bool,
    },
}

pub fn handle_command(command: PsbtCommand) -> Result<()> {
    match command {
        PsbtCommand::Parse { path, no_color } => {
            let raw_bytes = if path.to_str() == Some("-") {
                // Read from stdin
                let mut buffer = Vec::new();
                io::stdin()
                    .read_to_end(&mut buffer)
                    .context("Failed to read from stdin")?;
                buffer
            } else {
                // Read from file
                fs::read(&path)
                    .with_context(|| format!("Failed to read PSBT file: {}", path.display()))?
            };

            // Decode input (auto-detect base64, hex, or raw bytes)
            let bytes = decode_input(&raw_bytes)?;

            let node = parse_psbt_bytes_internal(&bytes)
                .map_err(|e| anyhow::anyhow!("Failed to parse PSBT: {}", e))?;

            let color_scheme = if no_color {
                ColorScheme::no_color()
            } else {
                ColorScheme::default()
            };

            render_tree_with_scheme(&node, &color_scheme)?;

            Ok(())
        }
    }
}
