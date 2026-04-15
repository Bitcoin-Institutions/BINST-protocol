//! `binst vault` — Derive vault addresses from admin public keys.

use binst_decoder::vault;
use bitcoin::Network;
use clap::Args;

#[derive(Args, Debug)]
pub struct VaultArgs {
    /// Admin x-only public key (64-char hex).
    #[arg(long)]
    pub admin: String,

    /// Use mainnet (default is testnet4).
    #[arg(long)]
    pub mainnet: bool,

    /// Output format: "text" or "json".
    #[arg(long, default_value = "text")]
    pub format: String,
}

pub fn run(args: &VaultArgs) -> Result<(), Box<dyn std::error::Error>> {
    let network = if args.mainnet { Network::Bitcoin } else { Network::Testnet };
    let admin_key = vault::parse_xonly(&args.admin)
        .map_err(|e| format!("bad admin pubkey: {e}"))?;
    let addr = vault::admin_vault_address(&admin_key, network)
        .map_err(|e| format!("vault derivation: {e}"))?;

    if args.format == "json" {
        let obj = serde_json::json!({
            "admin_pubkey": &args.admin,
            "network": if args.mainnet { "mainnet" } else { "testnet4" },
            "vault_address": addr,
            "descriptor": format!("tr(NUMS, {{pk({})}})", &args.admin[..16]),
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap());
    } else {
        println!("Network:      {}", if args.mainnet { "mainnet" } else { "testnet4" });
        println!("Admin:        {}", args.admin);
        println!("Vault:        {addr}");
        println!("Descriptor:   tr(NUMS, {{pk({}…)}}) ", &args.admin[..16]);
        println!("Key-path:     UNSPENDABLE (NUMS)");
        println!("Script-path:  Single leaf — admin spend");
    }
    Ok(())
}
