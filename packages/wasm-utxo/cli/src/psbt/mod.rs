use anyhow::Result;
use clap::Subcommand;

mod parse;

#[derive(Subcommand)]
pub enum PsbtCommand {
    /// Parse a PSBT file and display its contents
    Parse {
        /// Path to the PSBT file (use '-' to read from stdin)
        path: std::path::PathBuf,
        /// Disable colored output
        #[arg(long)]
        no_color: bool,
        /// Show raw key-value pairs instead of parsed structure
        #[arg(long)]
        raw: bool,
    },
}

pub fn handle_command(command: PsbtCommand) -> Result<()> {
    match command {
        PsbtCommand::Parse {
            path,
            no_color,
            raw,
        } => parse::handle_parse_command(path, no_color, raw),
    }
}

