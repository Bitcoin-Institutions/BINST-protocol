//! `binst scan` — Scan Bitcoin testnet4 for Citrea DA inscriptions.
//!
//! This is the original citrea-scanner functionality, now available
//! as a subcommand.

use clap::Args;

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Scan a specific block height.
    #[arg(long)]
    pub block: Option<u64>,

    /// Start of block range to scan.
    #[arg(long)]
    pub from: Option<u64>,

    /// End of block range to scan (inclusive).
    #[arg(long)]
    pub to: Option<u64>,

    /// Scan the latest N blocks from chain tip.
    #[arg(long)]
    pub latest: Option<u64>,

    /// Bitcoin Core RPC URL.
    #[arg(long, default_value = "http://127.0.0.1:48332")]
    pub rpc_url: String,

    /// RPC cookie file path.
    #[arg(long)]
    pub cookie: Option<String>,

    /// RPC username (alternative to cookie auth).
    #[arg(long)]
    pub rpc_user: Option<String>,

    /// RPC password (alternative to cookie auth).
    #[arg(long)]
    pub rpc_pass: Option<String>,

    /// Output format: "text" or "json".
    #[arg(long, default_value = "text")]
    pub format: String,

    /// Only show transactions of this type (0-4).
    #[arg(long)]
    pub kind: Option<u16>,

    /// Citrea L2 RPC URL — queries batch proofs via RPC instead of
    /// scanning Bitcoin blocks.
    #[arg(long)]
    pub citrea_rpc: Option<String>,

    /// Auto-discover all BINST contract addresses from the deployer.
    #[arg(long)]
    pub discover: bool,

    /// BINST deployer contract address (hex, 0x-prefixed).
    #[arg(long)]
    pub deployer: Option<String>,

    /// BINST institution contract addresses.
    #[arg(long, value_delimiter = ',')]
    pub institution: Vec<String>,

    /// BINST template contract addresses.
    #[arg(long, value_delimiter = ',')]
    pub template: Vec<String>,

    /// BINST instance contract addresses.
    #[arg(long, value_delimiter = ',')]
    pub instance: Vec<String>,
}

/// Run the scan subcommand by delegating to `crate::scanner::run`.
pub fn run(args: &ScanArgs) -> Result<(), Box<dyn std::error::Error>> {
    crate::scanner::run(args)
}
