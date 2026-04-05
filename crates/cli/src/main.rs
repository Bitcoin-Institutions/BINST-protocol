//! citrea-scanner — Scan Bitcoin testnet4 blocks for Citrea DA inscriptions.
//!
//! Connects to a local Bitcoin Core testnet4 node, iterates over blocks,
//! identifies Citrea reveal transactions by their wtxid prefix, and decodes
//! the tapscript inscriptions.
//!
//! Alternatively, queries the Citrea L2 RPC directly for batch proofs and
//! state diffs (--citrea-rpc mode).
//!
//! # Usage
//!
//! ```bash
//! # Scan a specific block via Bitcoin Core
//! citrea-scanner --block 127600
//!
//! # Scan via Citrea RPC (no local node required)
//! citrea-scanner --citrea-rpc https://rpc.testnet.citrea.xyz --block 127747
//! ```

mod citrea_rpc;

use bitcoincore_rpc::{Auth, Client, RpcApi};
use citrea_decoder::{
    extract_tapscript, has_citrea_prefix, parse_tapscript, DataOnDa, REVEAL_TX_PREFIX,
};
use citrea_decoder::proof::{decode_complete_proof, decompress_proof};
use binst_decoder::diff::{self, BinstRegistry};
use binst_decoder::jmt;
use clap::Parser;

/// Scan Bitcoin testnet4 for Citrea DA inscriptions.
#[derive(Parser, Debug)]
#[command(name = "citrea-scanner", about = "Decode Citrea inscriptions from Bitcoin testnet4")]
struct Args {
    /// Scan a specific block height.
    #[arg(long)]
    block: Option<u64>,

    /// Start of block range to scan.
    #[arg(long)]
    from: Option<u64>,

    /// End of block range to scan (inclusive).
    #[arg(long)]
    to: Option<u64>,

    /// Scan the latest N blocks from chain tip.
    #[arg(long)]
    latest: Option<u64>,

    /// Bitcoin Core RPC URL.
    #[arg(long, default_value = "http://127.0.0.1:48332")]
    rpc_url: String,

    /// RPC cookie file path (auto-detected if not specified).
    #[arg(long)]
    cookie: Option<String>,

    /// RPC username (alternative to cookie auth).
    #[arg(long)]
    rpc_user: Option<String>,

    /// RPC password (alternative to cookie auth).
    #[arg(long)]
    rpc_pass: Option<String>,

    /// Output format: "text" or "json".
    #[arg(long, default_value = "text")]
    format: String,

    /// Only show transactions of this type (0-4).
    #[arg(long)]
    kind: Option<u16>,

    /// Citrea L2 RPC URL — when set, queries batch proofs via RPC instead of
    /// scanning Bitcoin blocks. No local Bitcoin Core node required.
    #[arg(long)]
    citrea_rpc: Option<String>,

    /// Auto-discover all BINST contract addresses from the deployer.
    /// Requires --citrea-rpc and --deployer. Queries getInstitutions(),
    /// getDeployedProcesses(), getAllInstances() via eth_call.
    #[arg(long)]
    discover: bool,

    /// BINST deployer contract address (hex, 0x-prefixed).
    /// When set, state diffs are matched against BINST slots.
    #[arg(long)]
    deployer: Option<String>,

    /// BINST institution contract addresses (hex, 0x-prefixed, comma-separated).
    #[arg(long, value_delimiter = ',')]
    institution: Vec<String>,

    /// BINST template contract addresses (hex, 0x-prefixed, comma-separated).
    #[arg(long, value_delimiter = ',')]
    template: Vec<String>,

    /// BINST instance contract addresses (hex, 0x-prefixed, comma-separated).
    #[arg(long, value_delimiter = ',')]
    instance: Vec<String>,
}

fn get_auth(args: &Args) -> Auth {
    if let (Some(user), Some(pass)) = (&args.rpc_user, &args.rpc_pass) {
        Auth::UserPass(user.clone(), pass.clone())
    } else if let Some(cookie) = &args.cookie {
        Auth::CookieFile(cookie.into())
    } else {
        // Default testnet4 cookie location on macOS
        let home = std::env::var("HOME").unwrap_or_default();
        let cookie_path = format!("{home}/.bitcoin/testnet4/.cookie");
        if std::path::Path::new(&cookie_path).exists() {
            Auth::CookieFile(cookie_path.into())
        } else {
            eprintln!("Warning: No cookie file found at {cookie_path}, trying without auth");
            Auth::None
        }
    }
}

/// Parse a 0x-prefixed hex address string to [u8; 20].
fn parse_address(s: &str) -> Result<[u8; 20], String> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex address: {e}"))?;
    if bytes.len() != 20 {
        return Err(format!("address must be 20 bytes, got {}", bytes.len()));
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

/// Build a BinstRegistry from CLI arguments and optional discovery results.
/// Returns None if no BINST addresses were specified or discovered.
fn build_registry(
    args: &Args,
    discovered: Option<&citrea_rpc::DiscoveredContracts>,
) -> Option<BinstRegistry> {
    let has_any = args.deployer.is_some()
        || !args.institution.is_empty()
        || !args.template.is_empty()
        || !args.instance.is_empty()
        || discovered.is_some();

    if !has_any {
        return None;
    }

    let mut reg = BinstRegistry::new();

    if let Some(ref d) = args.deployer {
        match parse_address(d) {
            Ok(addr) => reg.add_deployer(addr),
            Err(e) => eprintln!("Warning: bad --deployer address: {e}"),
        }
    }
    for inst in &args.institution {
        match parse_address(inst) {
            Ok(addr) => reg.add_institution(addr),
            Err(e) => eprintln!("Warning: bad --institution address: {e}"),
        }
    }
    for tpl in &args.template {
        match parse_address(tpl) {
            Ok(addr) => reg.add_template(addr),
            Err(e) => eprintln!("Warning: bad --template address: {e}"),
        }
    }
    for inst in &args.instance {
        match parse_address(inst) {
            Ok(addr) => reg.add_instance(addr),
            Err(e) => eprintln!("Warning: bad --instance address: {e}"),
        }
    }

    // Merge discovered contracts
    if let Some(disc) = discovered {
        for addr in &disc.institutions {
            reg.add_institution(*addr);
        }
        for addr in &disc.templates {
            reg.add_template(*addr);
        }
        for addr in &disc.instances {
            reg.add_instance(*addr);
        }
    }

    reg.build_lookup();
    eprintln!(
        "BINST registry: {} contracts, {} pre-computed slot hashes",
        reg.len(),
        reg.lookup_table_size(),
    );

    Some(reg)
}

/// Compute the wtxid of a raw transaction.
/// wtxid = double-SHA256 of the serialized tx including witness.
fn compute_wtxid(raw_tx: &[u8]) -> [u8; 32] {
    use bitcoin::hashes::{sha256d, Hash};
    let hash = sha256d::Hash::hash(raw_tx);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_ref());
    result
}

fn scan_block(client: &Client, height: u64, args: &Args, registry: Option<&BinstRegistry>) -> Result<u64, Box<dyn std::error::Error>> {
    let block_hash = client.get_block_hash(height)?;
    let block = client.get_block(&block_hash)?;

    let mut found = 0u64;

    for (tx_idx, tx) in block.txdata.iter().enumerate() {
        if tx_idx == 0 {
            continue; // skip coinbase
        }

        // Serialize tx to compute wtxid
        let raw = bitcoin::consensus::serialize(tx);
        let wtxid = compute_wtxid(&raw);

        if !has_citrea_prefix(&wtxid, REVEAL_TX_PREFIX) {
            continue;
        }

        // Extract witness from first input
        let witness: Vec<Vec<u8>> = tx.input[0].witness.to_vec();

        let Some(tapscript_bytes) = extract_tapscript(&witness) else {
            continue;
        };

        let inscription = match parse_tapscript(tapscript_bytes) {
            Ok(i) => i,
            Err(e) => {
                eprintln!(
                    "  Block {height} tx[{tx_idx}]: parse error: {e} (wtxid {})",
                    hex::encode(wtxid)
                );
                continue;
            }
        };

        // Filter by kind if requested
        if let Some(filter_kind) = args.kind {
            if (inscription.kind as u16) != filter_kind {
                continue;
            }
        }

        found += 1;

        if args.format == "json" {
            print_json(height, tx_idx, tx, &wtxid, &inscription, registry);
        } else {
            print_text(height, tx_idx, tx, &wtxid, &inscription, registry);
        }
    }

    Ok(found)
}

fn print_text(
    height: u64,
    tx_idx: usize,
    tx: &bitcoin::Transaction,
    wtxid: &[u8; 32],
    inscription: &citrea_decoder::ParsedInscription,
    registry: Option<&BinstRegistry>,
) {
    println!(
        "Block {height} tx[{tx_idx}] — {} (wtxid: {}...)",
        inscription.kind,
        hex::encode(&wtxid[..4]),
    );
    println!("  txid:    {}", tx.compute_txid());
    println!("  pubkey:  {}", hex::encode(inscription.tapscript_pubkey));
    println!("  body:    {} bytes", inscription.body.len());

    match inscription.decode_body() {
        Ok(DataOnDa::SequencerCommitment(sc)) => {
            println!("  ── SequencerCommitment ──");
            println!("  index:         {}", sc.index);
            println!("  l2_end_block:  {}", sc.l2_end_block_number);
            println!("  merkle_root:   {}", hex::encode(sc.merkle_root));
        }
        Ok(DataOnDa::Complete(proof)) => {
            println!("  ── Complete Batch Proof ──");
            println!("  proof size:    {} bytes (compressed)", proof.len());

            // Attempt to decompress and decode
            match decode_complete_proof(&proof) {
                Ok(output) => {
                    let (start, end) = output.commitment_range();
                    println!("  ── Decoded Proof Output ──");
                    println!("  last_l2_height:     {}", output.last_l2_height());
                    println!("  state_roots:        {}", output.state_roots().len());
                    println!("  commitment_range:   {}..={}", start, end);
                    println!("  state_diff_entries: {}", output.state_diff_len());

                    if output.state_diff_len() > 0 {
                        println!("  ── State Diff (first 10) ──");
                        for (i, (key, value)) in output.state_diff().iter().take(10).enumerate() {
                            let val_str = match value {
                                Some(v) => format!("{} bytes", v.len()),
                                None => "DELETED".to_string(),
                            };
                            println!(
                                "  [{i}] key={} ({} bytes) → {val_str}",
                                hex::encode(&key[..std::cmp::min(8, key.len())]),
                                key.len()
                            );
                        }
                        if output.state_diff_len() > 10 {
                            println!("  ... and {} more entries", output.state_diff_len() - 10);
                        }

                        // BINST matching
                        if let Some(reg) = registry {
                            let changes = diff::map_state_diff(reg, output.state_diff());
                            if !changes.is_empty() {
                                println!("  ── BINST Changes ({}) ──", changes.len());
                                for ch in &changes {
                                    let addr_str = ch.contract_address
                                        .map(|a| format!("0x{}", hex::encode(a)))
                                        .unwrap_or_default();
                                    println!(
                                        "    {} {} → {} = {}",
                                        ch.contract, addr_str, ch.field, ch.decoded
                                    );
                                }
                            }
                        }

                        // JMT summary
                        let summary = jmt::summarize_diff(output.state_diff());
                        println!(
                            "  ── JMT summary: {} storage, {} headers, {} accounts, {} idx, {} other ──",
                            summary.evm_storage, summary.evm_header,
                            summary.evm_account, summary.evm_account_idx,
                            summary.other
                        );
                    }
                }
                Err(e) => {
                    // Try just decompression to show size
                    match decompress_proof(&proof) {
                        Ok(raw) => println!(
                            "  decompressed:  {} bytes (journal extraction failed: {e})",
                            raw.len()
                        ),
                        Err(de) => println!("  decompress failed: {de}"),
                    }
                }
            }
        }
        Ok(DataOnDa::Aggregate(txids, wtxids)) => {
            println!("  ── Aggregate ──");
            println!("  chunk txids:   {}", txids.len());
            println!("  chunk wtxids:  {}", wtxids.len());
        }
        Ok(DataOnDa::Chunk(data)) => {
            println!("  ── Chunk ──");
            println!("  chunk size:    {} bytes", data.len());
        }
        Ok(DataOnDa::BatchProofMethodId(m)) => {
            println!("  ── BatchProofMethodId ──");
            println!("  method_id:     {} bytes", m.method_id.len());
            println!("  signatures:    {}", m.signatures.len());
        }
        Err(e) => {
            println!("  ── Borsh decode error: {e} ──");
            println!("  raw body hex:  {}", hex::encode(&inscription.body));
        }
    }
    println!();
}

fn print_json(
    height: u64,
    tx_idx: usize,
    tx: &bitcoin::Transaction,
    wtxid: &[u8; 32],
    inscription: &citrea_decoder::ParsedInscription,
    registry: Option<&BinstRegistry>,
) {
    let mut obj = serde_json::json!({
        "block": height,
        "tx_index": tx_idx,
        "txid": tx.compute_txid().to_string(),
        "wtxid": hex::encode(wtxid),
        "kind": format!("{}", inscription.kind),
        "pubkey": hex::encode(inscription.tapscript_pubkey),
        "body_size": inscription.body.len(),
    });

    match inscription.decode_body() {
        Ok(DataOnDa::SequencerCommitment(sc)) => {
            obj["sequencer_commitment"] = serde_json::json!({
                "index": sc.index,
                "l2_end_block_number": sc.l2_end_block_number,
                "merkle_root": hex::encode(sc.merkle_root),
            });
        }
        Ok(DataOnDa::Complete(proof)) => {
            let mut proof_obj = serde_json::json!({
                "compressed_size": proof.len(),
            });

            match decode_complete_proof(&proof) {
                Ok(output) => {
                    let (start, end) = output.commitment_range();
                    proof_obj["last_l2_height"] = serde_json::json!(output.last_l2_height());
                    proof_obj["state_roots_count"] = serde_json::json!(output.state_roots().len());
                    proof_obj["commitment_range"] = serde_json::json!([start, end]);
                    proof_obj["state_diff_entries"] = serde_json::json!(output.state_diff_len());

                    // Include all state diff entries (capped at 5000 for safety)
                    let diffs: Vec<serde_json::Value> = output
                        .state_diff()
                        .iter()
                        .take(20)
                        .map(|(key, value)| {
                            serde_json::json!({
                                "key": hex::encode(key),
                                "value": value.as_ref().map(hex::encode),
                            })
                        })
                        .collect();
                    proof_obj["state_diff_sample"] = serde_json::json!(diffs);

                    // BINST matching
                    if let Some(reg) = registry {
                        let changes = diff::map_state_diff(reg, output.state_diff());
                        if !changes.is_empty() {
                            let binst_changes: Vec<serde_json::Value> = changes.iter().map(|ch| {
                                serde_json::json!({
                                    "contract": format!("{}", ch.contract),
                                    "address": ch.contract_address.map(|a| format!("0x{}", hex::encode(a))),
                                    "field": format!("{}", ch.field),
                                    "decoded": format!("{}", ch.decoded),
                                    "raw_value": ch.raw_value,
                                })
                            }).collect();
                            proof_obj["binst_changes"] = serde_json::json!(binst_changes);
                        }
                    }

                    // JMT summary
                    let summary = jmt::summarize_diff(output.state_diff());
                    proof_obj["jmt_summary"] = serde_json::json!({
                        "evm_storage": summary.evm_storage,
                        "evm_header": summary.evm_header,
                        "evm_account": summary.evm_account,
                        "evm_account_idx": summary.evm_account_idx,
                        "other": summary.other,
                    });
                }
                Err(e) => {
                    proof_obj["decode_error"] = serde_json::json!(format!("{e}"));
                }
            }

            obj["complete_proof"] = proof_obj;
        }
        Ok(DataOnDa::Aggregate(txids, _wtxids)) => {
            obj["aggregate"] = serde_json::json!({
                "chunk_count": txids.len(),
                "chunk_txids": txids.iter().map(hex::encode).collect::<Vec<_>>(),
            });
        }
        _ => {}
    }

    println!("{}", serde_json::to_string_pretty(&obj).unwrap());
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // ── Discovery: auto-discover BINST contracts via Citrea RPC ──
    let discovered = if args.discover {
        let rpc_url = args.citrea_rpc.as_deref().ok_or(
            "--discover requires --citrea-rpc <URL>",
        )?;
        let deployer_hex = args.deployer.as_deref().ok_or(
            "--discover requires --deployer <ADDRESS>",
        )?;
        let deployer_addr = format!(
            "0x{}",
            deployer_hex
                .strip_prefix("0x")
                .or_else(|| deployer_hex.strip_prefix("0X"))
                .unwrap_or(deployer_hex)
        );
        let client = citrea_rpc::CitreaClient::new(rpc_url);
        match client.discover_binst_contracts(&deployer_addr) {
            Ok(disc) => {
                eprintln!("Discovered BINST contracts:");
                eprintln!(
                    "  {} institution(s): {}",
                    disc.institutions.len(),
                    disc.institutions
                        .iter()
                        .map(|a| format!("0x{}", hex::encode(a)))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                eprintln!(
                    "  {} template(s):    {}",
                    disc.templates.len(),
                    disc.templates
                        .iter()
                        .map(|a| format!("0x{}", hex::encode(a)))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                eprintln!(
                    "  {} instance(s):    {}",
                    disc.instances.len(),
                    disc.instances
                        .iter()
                        .map(|a| format!("0x{}", hex::encode(a)))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                Some(disc)
            }
            Err(e) => {
                eprintln!("Warning: contract discovery failed: {e}");
                None
            }
        }
    } else {
        None
    };

    let registry = build_registry(&args, discovered.as_ref());

    if let Some(ref citrea_url) = args.citrea_rpc {
        return run_rpc_mode(citrea_url, &args, registry.as_ref());
    }

    // ── Bitcoin Core scanning mode ──
    let auth = get_auth(&args);
    let client = Client::new(&args.rpc_url, auth)?;

    // Verify connection
    let info = client.get_blockchain_info()?;
    eprintln!(
        "Connected to {} (block {})",
        info.chain, info.blocks
    );

    // Determine block range to scan
    let (from, to) = if let Some(block) = args.block {
        (block, block)
    } else if let Some(latest) = args.latest {
        let tip = info.blocks as u64;
        (tip.saturating_sub(latest - 1), tip)
    } else {
        let from = args.from.unwrap_or(info.blocks as u64);
        let to = args.to.unwrap_or(from);
        (from, to)
    };

    eprintln!("Scanning blocks {from}..={to} ({} blocks)", to - from + 1);
    eprintln!();

    let mut total_found = 0u64;
    for height in from..=to {
        match scan_block(&client, height, &args, registry.as_ref()) {
            Ok(n) => total_found += n,
            Err(e) => eprintln!("Error scanning block {height}: {e}"),
        }
    }

    eprintln!("Found {total_found} Citrea inscription(s)");
    Ok(())
}

// ── Citrea RPC mode ─────────────────────────────────────────────

/// Query batch proofs from the Citrea L2 RPC instead of scanning Bitcoin blocks.
fn run_rpc_mode(
    citrea_url: &str,
    args: &Args,
    registry: Option<&BinstRegistry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = citrea_rpc::CitreaClient::new(citrea_url);

    // Show proven height
    match client.get_last_proven_height() {
        Ok(h) => eprintln!(
            "Citrea last proven L2 height: {} (commitment index {})",
            h.height, h.commitment_index
        ),
        Err(e) => eprintln!("Warning: could not get proven height: {e}"),
    }

    // Determine block range
    let (from, to) = if let Some(block) = args.block {
        (block, block)
    } else if let Some(latest) = args.latest {
        // We can't know the Bitcoin tip from the Citrea RPC easily,
        // so require --block or --from/--to in RPC mode.
        return Err(format!(
            "--latest requires Bitcoin Core; use --block or --from/--to in RPC mode \
             (latest={latest})"
        )
        .into());
    } else {
        let from = args.from.ok_or("--block or --from required in RPC mode")?;
        let to = args.to.unwrap_or(from);
        (from, to)
    };

    eprintln!(
        "Querying Citrea RPC for BTC blocks {from}..={to} ({} blocks)",
        to - from + 1
    );
    eprintln!();

    let mut total_proofs = 0u64;
    let mut total_entries = 0usize;

    for btc_height in from..=to {
        match client.get_verified_batch_proofs(btc_height) {
            Ok(proofs) if proofs.is_empty() => {
                if args.format != "json" {
                    eprintln!("Block {btc_height}: no verified batch proofs");
                }
            }
            Ok(proofs) => {
                total_proofs += proofs.len() as u64;
                for (proof_idx, proof) in proofs.iter().enumerate() {
                    let state_diff =
                        citrea_rpc::state_diff_from_rpc(&proof.proof_output.state_diff);
                    total_entries += state_diff.len();

                    if args.format == "json" {
                        print_rpc_json(btc_height, proof_idx, proof, &state_diff, registry);
                    } else {
                        print_rpc_text(btc_height, proof_idx, proof, &state_diff, registry);
                    }
                }
            }
            Err(e) => eprintln!("Error querying block {btc_height}: {e}"),
        }
    }

    eprintln!(
        "Total: {total_proofs} batch proof(s), {total_entries} state diff entries"
    );
    Ok(())
}

fn print_rpc_text(
    btc_height: u64,
    proof_idx: usize,
    proof: &citrea_rpc::RpcBatchProof,
    state_diff: &[(Vec<u8>, Option<Vec<u8>>)],
    registry: Option<&BinstRegistry>,
) {
    let out = &proof.proof_output;
    println!(
        "BTC block {btc_height} proof[{proof_idx}] — {} state roots, {} state diff entries",
        out.state_roots.len(),
        state_diff.len(),
    );
    println!("  final_l2_hash: {}", out.final_l2_block_hash);

    // JMT summary
    let summary = jmt::summarize_diff(state_diff);
    println!(
        "  JMT: {} storage, {} headers, {} accounts, {} idx, {} other",
        summary.evm_storage,
        summary.evm_header,
        summary.evm_account,
        summary.evm_account_idx,
        summary.other,
    );

    // State diff sample (first 10)
    if !state_diff.is_empty() {
        println!("  ── State Diff (first 10) ──");
        for (i, (key, value)) in state_diff.iter().take(10).enumerate() {
            let val_str = match value {
                Some(v) => format!("{} bytes", v.len()),
                None => "DELETED".to_string(),
            };
            println!(
                "  [{i}] key={} ({} bytes) → {val_str}",
                hex::encode(&key[..std::cmp::min(8, key.len())]),
                key.len()
            );
        }
        if state_diff.len() > 10 {
            println!("  ... and {} more entries", state_diff.len() - 10);
        }
    }

    // BINST matching
    if let Some(reg) = registry {
        let changes = diff::map_state_diff(reg, state_diff);
        if changes.is_empty() {
            println!("  BINST: no matching slot changes");
        } else {
            println!("  ── BINST Changes ({}) ──", changes.len());
            for ch in &changes {
                let addr_str = ch
                    .contract_address
                    .map(|a| format!("0x{}", hex::encode(a)))
                    .unwrap_or_default();
                println!(
                    "    {} {} → {} = {}",
                    ch.contract, addr_str, ch.field, ch.decoded
                );
            }
        }
    }

    println!();
}

fn print_rpc_json(
    btc_height: u64,
    proof_idx: usize,
    proof: &citrea_rpc::RpcBatchProof,
    state_diff: &[(Vec<u8>, Option<Vec<u8>>)],
    registry: Option<&BinstRegistry>,
) {
    let out = &proof.proof_output;
    let summary = jmt::summarize_diff(state_diff);

    let mut obj = serde_json::json!({
        "btc_block": btc_height,
        "proof_index": proof_idx,
        "source": "citrea_rpc",
        "state_roots_count": out.state_roots.len(),
        "state_diff_entries": state_diff.len(),
        "final_l2_block_hash": out.final_l2_block_hash,
        "jmt_summary": {
            "evm_storage": summary.evm_storage,
            "evm_header": summary.evm_header,
            "evm_account": summary.evm_account,
            "evm_account_idx": summary.evm_account_idx,
            "other": summary.other,
        },
    });

    // State diff sample
    let sample: Vec<serde_json::Value> = state_diff
        .iter()
        .take(20)
        .map(|(key, value)| {
            serde_json::json!({
                "key": hex::encode(key),
                "value": value.as_ref().map(hex::encode),
            })
        })
        .collect();
    obj["state_diff_sample"] = serde_json::json!(sample);

    // BINST matching
    if let Some(reg) = registry {
        let changes = diff::map_state_diff(reg, state_diff);
        if !changes.is_empty() {
            let binst_changes: Vec<serde_json::Value> = changes
                .iter()
                .map(|ch| {
                    serde_json::json!({
                        "contract": format!("{}", ch.contract),
                        "address": ch.contract_address.map(|a| format!("0x{}", hex::encode(a))),
                        "field": format!("{}", ch.field),
                        "decoded": format!("{}", ch.decoded),
                        "raw_value": ch.raw_value,
                    })
                })
                .collect();
            obj["binst_changes"] = serde_json::json!(binst_changes);
        }
    }

    println!("{}", serde_json::to_string_pretty(&obj).unwrap());
}
