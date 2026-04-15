//! BINST sovereign CLI toolkit.
//!
//! Subcommands:
//!   scan      — Scan Bitcoin blocks for Citrea DA inscriptions
//!   finality  — Query Bitcoin settlement status of Citrea L2
//!   factory   — Query BINSTProcessFactory on Citrea
//!   instance  — Query a deployed BINSTProcess contract
//!   vault     — Derive vault addresses from admin pubkeys
//!
//! The `scan` subcommand preserves all original citrea-scanner functionality.
//! When invoked as `citrea-scanner` (binary alias), it runs `scan` directly.

mod citrea_rpc;
mod cmd;
mod scanner;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "binst",
    about = "BINST sovereign CLI toolkit — inscribe, query, scan, verify"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan Bitcoin testnet4 for Citrea DA inscriptions.
    Scan(cmd::scan::ScanArgs),
    /// Query Bitcoin settlement finality of Citrea L2 blocks.
    Finality(cmd::finality::FinalityArgs),
    /// Query BINSTProcessFactory contract on Citrea.
    Factory(cmd::factory::FactoryArgs),
    /// Query a deployed BINSTProcess instance on Citrea.
    Instance(cmd::instance::InstanceArgs),
    /// Derive vault addresses from admin public keys.
    Vault(cmd::vault::VaultArgs),
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan(ref args) => cmd::scan::run(args),
        Commands::Finality(ref args) => cmd::finality::run(args),
        Commands::Factory(ref args) => cmd::factory::run(args),
        Commands::Instance(ref args) => cmd::instance::run(args),
        Commands::Vault(ref args) => cmd::vault::run(args),
    }
}
