//! `binst finality` — Query Bitcoin settlement status of Citrea L2 blocks.
//!
//! Reports committed/proven boundaries and optionally classifies specific
//! transaction hashes or L2 block numbers.

use binst_evm::rpc::RpcClient;
use binst_evm::types::FinalityTier;
use clap::Args;

#[derive(Args, Debug)]
pub struct FinalityArgs {
    /// Citrea RPC URL.
    #[arg(long, default_value = "https://rpc.testnet.citrea.xyz")]
    pub rpc_url: String,

    /// Classify a specific L2 block number.
    #[arg(long)]
    pub block: Option<u64>,

    /// Classify a specific transaction hash (reads block number from receipt).
    #[arg(long)]
    pub tx: Option<String>,

    /// Find the sequencer batch that contains a given L2 block.
    #[arg(long)]
    pub find_batch: Option<u64>,

    /// Output format: "text" or "json".
    #[arg(long, default_value = "text")]
    pub format: String,
}

pub fn run(args: &FinalityArgs) -> Result<(), Box<dyn std::error::Error>> {
    let client = RpcClient::new(&args.rpc_url);

    // Always show boundaries
    let status = client.get_finality_status().map_err(|e| format!("{e}"))?;
    let l2_tip = client.block_number().map_err(|e| format!("{e}"))?;

    if args.format == "json" {
        let mut obj = serde_json::json!({
            "l2_tip": l2_tip,
            "committed_height": status.committed_height,
            "committed_batch_index": status.committed_batch_index,
            "proven_height": status.proven_height,
            "proven_batch_index": status.proven_batch_index,
        });

        if let Some(block) = args.block {
            let tier = FinalityTier::classify(block, &status);
            obj["query_block"] = serde_json::json!({
                "block": block,
                "tier": tier.label(),
            });
        }

        if let Some(ref tx_hash) = args.tx {
            match client.get_tx_block_number(tx_hash) {
                Ok(block) => {
                    let tier = FinalityTier::classify(block, &status);
                    obj["query_tx"] = serde_json::json!({
                        "tx_hash": tx_hash,
                        "block": block,
                        "tier": tier.label(),
                    });
                }
                Err(e) => {
                    obj["query_tx"] = serde_json::json!({
                        "tx_hash": tx_hash,
                        "error": format!("{e}"),
                    });
                }
            }
        }

        if let Some(target) = args.find_batch {
            match client.find_batch_for_block(target, 1, status.committed_batch_index) {
                Ok((batch_idx, end_block)) => {
                    obj["query_batch"] = serde_json::json!({
                        "target_block": target,
                        "batch_index": batch_idx,
                        "batch_end_block": end_block,
                    });
                }
                Err(e) => {
                    obj["query_batch"] = serde_json::json!({
                        "target_block": target,
                        "error": format!("{e}"),
                    });
                }
            }
        }

        println!("{}", serde_json::to_string_pretty(&obj).unwrap());
    } else {
        println!("Citrea L2 Settlement Status");
        println!("───────────────────────────");
        println!("  L2 tip:              {l2_tip}");
        println!(
            "  Committed boundary:  {} (batch {})",
            status.committed_height, status.committed_batch_index
        );
        println!(
            "  Proven boundary:     {} (batch {})",
            status.proven_height, status.proven_batch_index
        );
        println!(
            "  Uncommitted gap:     {} blocks",
            l2_tip.saturating_sub(status.committed_height)
        );
        println!(
            "  Unproven gap:        {} blocks",
            status.committed_height.saturating_sub(status.proven_height)
        );

        if let Some(block) = args.block {
            let tier = FinalityTier::classify(block, &status);
            println!();
            println!("  Block {block}: {}", tier.label());
        }

        if let Some(ref tx_hash) = args.tx {
            println!();
            match client.get_tx_block_number(tx_hash) {
                Ok(block) => {
                    let tier = FinalityTier::classify(block, &status);
                    println!("  Tx {tx_hash}");
                    println!("    L2 block: {block}");
                    println!("    Status:   {}", tier.label());
                }
                Err(e) => {
                    println!("  Tx {tx_hash}: error — {e}");
                }
            }
        }

        if let Some(target) = args.find_batch {
            println!();
            match client.find_batch_for_block(target, 1, status.committed_batch_index) {
                Ok((batch_idx, end_block)) => {
                    println!("  Block {target} is in batch {batch_idx} (ends at {end_block})");
                }
                Err(e) => {
                    println!("  Batch search for block {target}: error — {e}");
                }
            }
        }
    }

    Ok(())
}
