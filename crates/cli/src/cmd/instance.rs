//! `binst instance` — Query a deployed BINSTProcess contract on Citrea.
//!
//! Reads step count, current step, completion status, creator, template inscription ID,
//! and per-step details.

use binst_evm::abi;
use binst_evm::rpc::RpcClient;
use binst_evm::selectors;
use binst_evm::types::{FinalityTier, StepStatus};
use clap::Args;

#[derive(Args, Debug)]
pub struct InstanceArgs {
    /// BINSTProcess contract address.
    #[arg(long)]
    pub address: String,

    /// Citrea RPC URL.
    #[arg(long, default_value = "https://rpc.testnet.citrea.xyz")]
    pub rpc_url: String,

    /// Also check finality status of the creation tx hash.
    #[arg(long)]
    pub creation_tx: Option<String>,

    /// Output format: "text" or "json".
    #[arg(long, default_value = "text")]
    pub format: String,
}

pub fn run(args: &InstanceArgs) -> Result<(), Box<dyn std::error::Error>> {
    let client = RpcClient::new(&args.rpc_url);
    let addr = &args.address;

    let total_steps = client.get_total_steps(addr).map_err(|e| format!("{e}"))?;
    let current_step = client
        .get_current_step_index(addr)
        .map_err(|e| format!("{e}"))?;
    let completed = client.is_completed(addr).map_err(|e| format!("{e}"))?;
    let creator = client.get_creator(addr).map_err(|e| format!("{e}"))?;
    let template_id = client
        .get_template_inscription_id(addr)
        .map_err(|e| format!("{e}"))?;

    // Read per-step details
    let mut steps = Vec::new();
    for i in 0..total_steps {
        let step_info = read_step(&client, addr, i);
        steps.push(step_info);
    }

    // Optionally check finality
    let finality_info = if let Some(ref tx_hash) = args.creation_tx {
        match client.get_finality_status() {
            Ok(status) => match client.get_tx_block_number(tx_hash) {
                Ok(block) => {
                    let tier = FinalityTier::classify(block, &status);
                    Some((block, tier.label().to_string()))
                }
                Err(e) => {
                    eprintln!("Warning: could not get tx block: {e}");
                    None
                }
            },
            Err(e) => {
                eprintln!("Warning: could not get finality status: {e}");
                None
            }
        }
    } else {
        None
    };

    if args.format == "json" {
        let steps_json: Vec<serde_json::Value> = steps
            .iter()
            .enumerate()
            .map(|(i, s)| {
                serde_json::json!({
                    "index": i,
                    "name": s.name,
                    "action_type": s.action_type,
                    "status": s.status_label,
                })
            })
            .collect();

        let mut obj = serde_json::json!({
            "address": addr,
            "creator": creator,
            "template_inscription_id": template_id,
            "total_steps": total_steps,
            "current_step_index": current_step,
            "completed": completed,
            "steps": steps_json,
        });

        if let Some((block, tier)) = finality_info {
            obj["creation_finality"] = serde_json::json!({
                "tx_hash": args.creation_tx,
                "block": block,
                "tier": tier,
            });
        }

        println!("{}", serde_json::to_string_pretty(&obj).unwrap());
    } else {
        println!("BINSTProcess: {addr}");
        println!("  Creator:    {creator}");
        println!("  Template:   {template_id}");
        println!("  Steps:      {current_step}/{total_steps}");
        println!(
            "  Completed:  {}",
            if completed { "✅ yes" } else { "❌ no" }
        );

        if !steps.is_empty() {
            println!();
            println!("  Steps:");
            for (i, s) in steps.iter().enumerate() {
                let marker = if i < current_step as usize {
                    "✅"
                } else if i == current_step as usize && !completed {
                    "▶"
                } else {
                    "⬜"
                };
                println!(
                    "    {marker} [{i}] {} ({}) — {}",
                    s.name, s.action_type, s.status_label
                );
            }
        }

        if let Some((block, tier)) = finality_info {
            println!();
            println!("  Creation tx finality:");
            println!("    L2 block: {block}");
            println!("    Status:   {tier}");
        }
    }

    Ok(())
}

struct StepInfo {
    name: String,
    action_type: String,
    status_label: String,
}

fn read_step(client: &RpcClient, instance: &str, index: u64) -> StepInfo {
    // getStep(uint256) returns (string name, string actionType)
    let get_step_data = format!(
        "0x{}{}",
        hex::encode(selectors::GET_STEP),
        abi::encode_uint256(index)
    );
    let (name, action_type) = match client.eth_call(instance, &get_step_data) {
        Ok(result) => decode_step_tuple(&result),
        Err(e) => {
            eprintln!("Warning: getStep({index}) failed: {e}");
            ("?".to_string(), "?".to_string())
        }
    };

    // getStepState(uint256) returns uint8
    let get_state_data = format!(
        "0x{}{}",
        hex::encode(selectors::GET_STEP_STATE),
        abi::encode_uint256(index)
    );
    let status_label = match client.eth_call(instance, &get_state_data) {
        Ok(result) => {
            let hex = result.strip_prefix("0x").unwrap_or(&result);
            if hex.len() >= 64 {
                let val = abi::decode_uint256(&hex[0..64]).unwrap_or(99);
                match StepStatus::from_u8(val as u8) {
                    Some(StepStatus::Pending) => "Pending".to_string(),
                    Some(StepStatus::Completed) => "Completed".to_string(),
                    Some(StepStatus::Rejected) => "Rejected".to_string(),
                    None => format!("Unknown({val})"),
                }
            } else {
                "?".to_string()
            }
        }
        Err(e) => {
            eprintln!("Warning: getStepState({index}) failed: {e}");
            "?".to_string()
        }
    };

    StepInfo {
        name,
        action_type,
        status_label,
    }
}

/// Decode `(string, string)` ABI return from `getStep()`.
fn decode_step_tuple(result: &str) -> (String, String) {
    let hex = result.strip_prefix("0x").unwrap_or(result);
    if hex.len() < 128 {
        return ("?".to_string(), "?".to_string());
    }

    // Two offset words, then two dynamic strings
    let offset1 = usize::from_str_radix(&hex[0..64], 16).unwrap_or(0) * 2;
    let offset2 = usize::from_str_radix(&hex[64..128], 16).unwrap_or(0) * 2;

    let name = if offset1 + 64 <= hex.len() {
        abi::decode_string(&hex[offset1..]).unwrap_or_else(|_| "?".to_string())
    } else {
        "?".to_string()
    };

    let action_type = if offset2 + 64 <= hex.len() {
        abi::decode_string(&hex[offset2..]).unwrap_or_else(|_| "?".to_string())
    } else {
        "?".to_string()
    };

    (name, action_type)
}
