use anyhow::Result;
use clap::{Parser, Subcommand};

mod address;
mod format;
mod node;
mod parse_node;
mod psbt;

#[derive(Parser)]
#[command(name = "wasm-utxo-cli")]
#[command(about = "CLI tool for Bitcoin UTXO operations", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Address encoding and decoding operations
    Address {
        #[command(subcommand)]
        command: address::AddressCommand,
    },
    /// PSBT parsing and inspection operations
    Psbt {
        #[command(subcommand)]
        command: psbt::PsbtCommand,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Address { command } => address::handle_command(command),
        Commands::Psbt { command } => psbt::handle_command(command),
    }
}
