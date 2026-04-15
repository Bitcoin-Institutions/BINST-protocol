//! `binst factory` — Query BINSTProcessFactory contract on Citrea.
//!
//! Read instance count, list instances by template, list user instances.

use binst_evm::abi;
use binst_evm::rpc::RpcClient;
use binst_evm::selectors;
use clap::Args;

/// Default factory address on Citrea testnet (deployed 2026-04-09).
const DEFAULT_FACTORY: &str = "0x6a1d2adbac8682773ed6700d2118c709c8ce5000";

#[derive(Args, Debug)]
pub struct FactoryArgs {
    /// Citrea RPC URL.
    #[arg(long, default_value = "https://rpc.testnet.citrea.xyz")]
    pub rpc_url: String,

    /// Factory contract address (defaults to Citrea testnet deployment).
    #[arg(long, default_value = DEFAULT_FACTORY)]
    pub factory: String,

    /// Show all instances created from this template inscription ID.
    #[arg(long)]
    pub template: Option<String>,

    /// Show all instances created by this address.
    #[arg(long)]
    pub creator: Option<String>,

    /// Output format: "text" or "json".
    #[arg(long, default_value = "text")]
    pub format: String,
}

pub fn run(args: &FactoryArgs) -> Result<(), Box<dyn std::error::Error>> {
    let client = RpcClient::new(&args.rpc_url);

    // Read instance count
    let count = client
        .get_instance_count(&args.factory)
        .map_err(|e| format!("{e}"))?;

    if args.format == "json" {
        let mut obj = serde_json::json!({
            "factory": &args.factory,
            "instance_count": count,
        });

        if let Some(ref template_id) = args.template {
            match list_template_instances(&client, &args.factory, template_id) {
                Ok(addrs) => {
                    obj["template_instances"] = serde_json::json!({
                        "template_inscription_id": template_id,
                        "count": addrs.len(),
                        "addresses": addrs,
                    });
                }
                Err(e) => {
                    obj["template_instances_error"] = serde_json::json!(format!("{e}"));
                }
            }
        }

        if let Some(ref creator_addr) = args.creator {
            match list_user_instances(&client, &args.factory, creator_addr) {
                Ok(addrs) => {
                    obj["user_instances"] = serde_json::json!({
                        "creator": creator_addr,
                        "count": addrs.len(),
                        "addresses": addrs,
                    });
                }
                Err(e) => {
                    obj["user_instances_error"] = serde_json::json!(format!("{e}"));
                }
            }
        }

        println!("{}", serde_json::to_string_pretty(&obj).unwrap());
    } else {
        println!("BINSTProcessFactory: {}", args.factory);
        println!("  Total instances: {count}");

        if let Some(ref template_id) = args.template {
            println!();
            match list_template_instances(&client, &args.factory, template_id) {
                Ok(addrs) => {
                    println!(
                        "  Instances for template \"{template_id}\": {}",
                        addrs.len()
                    );
                    for addr in &addrs {
                        println!("    {addr}");
                    }
                }
                Err(e) => println!("  Template query error: {e}"),
            }
        }

        if let Some(ref creator_addr) = args.creator {
            println!();
            match list_user_instances(&client, &args.factory, creator_addr) {
                Ok(addrs) => {
                    println!(
                        "  Instances by creator {creator_addr}: {}",
                        addrs.len()
                    );
                    for addr in &addrs {
                        println!("    {addr}");
                    }
                }
                Err(e) => println!("  User query error: {e}"),
            }
        }
    }

    Ok(())
}

/// Call `getTemplateInstances(string)` → `address[]`.
fn list_template_instances(
    client: &RpcClient,
    factory: &str,
    template_id: &str,
) -> Result<Vec<String>, String> {
    let calldata = abi::encode_get_template_instances(template_id);
    let result = client.eth_call(factory, &calldata)?;
    let hex = result.strip_prefix("0x").unwrap_or(&result);
    decode_address_array_from_hex(hex)
}

/// Call `getUserInstances(address)` → `address[]`.
fn list_user_instances(
    client: &RpcClient,
    factory: &str,
    creator: &str,
) -> Result<Vec<String>, String> {
    let data = format!(
        "0x{}{}",
        hex::encode(selectors::GET_USER_INSTANCES),
        abi::encode_address(creator)
    );
    let result = client.eth_call(factory, &data)?;
    let hex = result.strip_prefix("0x").unwrap_or(&result);
    decode_address_array_from_hex(hex)
}

/// Decode ABI `address[]` from hex string into `Vec<"0x...">`  addresses.
fn decode_address_array_from_hex(hex: &str) -> Result<Vec<String>, String> {
    if hex.len() < 128 {
        return Ok(Vec::new());
    }
    // offset (64 hex chars = 32 bytes)
    let offset = usize::from_str_radix(&hex[0..64], 16)
        .map_err(|e| format!("offset: {e}"))?;
    let offset_hex = offset * 2;
    if offset_hex + 64 > hex.len() {
        return Err("offset out of bounds".to_string());
    }
    // length
    let length = usize::from_str_radix(&hex[offset_hex..offset_hex + 64], 16)
        .map_err(|e| format!("length: {e}"))?;

    let mut addrs = Vec::with_capacity(length);
    for i in 0..length {
        let start = offset_hex + 64 + i * 64;
        if start + 64 > hex.len() {
            break;
        }
        let addr_hex = &hex[start + 24..start + 64]; // last 20 bytes = 40 hex chars
        addrs.push(format!("0x{addr_hex}"));
    }
    Ok(addrs)
}
