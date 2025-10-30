use anyhow::{Context, Result};
use clap::Subcommand;
use wasm_utxo::bitcoin::Script;
use wasm_utxo::{from_output_script_with_network, to_output_script_with_network, Network};

#[derive(Subcommand)]
pub enum AddressCommand {
    /// Decode an address to its output script (hex)
    Decode {
        /// The address to decode
        address: String,
        /// Network (bitcoin, testnet, litecoin, zcash, etc.)
        #[arg(short, long, default_value = "bitcoin")]
        network: String,
    },
    /// Encode an output script (hex) to an address
    Encode {
        /// Output script as hex
        script: String,
        /// Network (bitcoin, testnet, litecoin, zcash, etc.)
        #[arg(short, long, default_value = "bitcoin")]
        network: String,
    },
}

pub fn handle_command(command: AddressCommand) -> Result<()> {
    match command {
        AddressCommand::Decode { address, network } => {
            let network = parse_network(&network)?;
            let script = to_output_script_with_network(&address, network)
                .context("Failed to decode address")?;
            println!("{}", hex::encode(script.as_bytes()));
            Ok(())
        }
        AddressCommand::Encode { script, network } => {
            let network = parse_network(&network)?;
            let script_bytes =
                hex::decode(&script).context("Invalid hex string for output script")?;
            let script_obj = Script::from_bytes(&script_bytes);
            let address = from_output_script_with_network(script_obj, network)
                .context("Failed to encode output script to address")?;
            println!("{}", address);
            Ok(())
        }
    }
}

fn parse_network(network: &str) -> Result<Network> {
    // Try utxolib name first (e.g., "bitcoin", "testnet", "bitcoincash")
    if let Some(net) = Network::from_utxolib_name(network) {
        return Ok(net);
    }

    // Try coin name (e.g., "btc", "ltc", "bch")
    if let Some(net) = Network::from_coin_name(network) {
        return Ok(net);
    }

    // Try common aliases
    let normalized = network.to_lowercase();
    match normalized.as_str() {
        "test" | "testnet3" => Ok(Network::BitcoinTestnet3),
        "signet" => Ok(Network::BitcoinPublicSignet),
        "ltctest" => Ok(Network::LitecoinTestnet),
        "bchtest" => Ok(Network::BitcoinCashTestnet),
        "bsvtest" => Ok(Network::BitcoinSVTestnet),
        "btgtest" => Ok(Network::BitcoinGoldTestnet),
        "dashtest" => Ok(Network::DashTestnet),
        "zectest" => Ok(Network::ZcashTestnet),
        "dogetest" => Ok(Network::DogecoinTestnet),
        "xec" => Ok(Network::Ecash),
        "xectest" => Ok(Network::EcashTestnet),
        _ => anyhow::bail!("Unknown network: {}", network),
    }
}
