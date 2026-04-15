//! Scanner module — extracted from the original citrea-scanner main.rs.
//!
//! Scans Bitcoin testnet4 blocks for Citrea DA inscriptions, either via
//! Bitcoin Core RPC or Citrea L2 RPC.

use crate::citrea_rpc;
use crate::cmd::scan::ScanArgs;

use binst_decoder::diff::{self, BinstRegistry};
use binst_decoder::jmt;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use citrea_decoder::proof::{decode_complete_proof, decompress_proof};
use citrea_decoder::{extract_tapscript, has_citrea_prefix, parse_tapscript, DataOnDa, REVEAL_TX_PREFIX};

// ── Entry point ─────────────────────────────────────────────────

pub fn run(args: &ScanArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Discovery
    let discovered = if args.discover {
        let rpc_url = args.citrea_rpc.as_deref().ok_or("--discover requires --citrea-rpc")?;
        let deployer_hex = args.deployer.as_deref().ok_or("--discover requires --deployer")?;
        let deployer_addr = format!(
            "0x{}",
            deployer_hex.strip_prefix("0x").or_else(|| deployer_hex.strip_prefix("0X")).unwrap_or(deployer_hex)
        );
        let client = citrea_rpc::CitreaClient::new(rpc_url);
        match client.discover_binst_contracts(&deployer_addr) {
            Ok(disc) => {
                eprintln!("Discovered {} inst, {} tpl, {} instance",
                    disc.institutions.len(), disc.templates.len(), disc.instances.len());
                Some(disc)
            }
            Err(e) => { eprintln!("Warning: discovery failed: {e}"); None }
        }
    } else {
        None
    };

    let registry = build_registry(args, discovered.as_ref());

    if let Some(ref citrea_url) = args.citrea_rpc {
        return run_rpc_mode(citrea_url, args, registry.as_ref());
    }

    // Bitcoin Core scanning mode
    let auth = get_auth(args);
    let client = Client::new(&args.rpc_url, auth)?;
    let info = client.get_blockchain_info()?;
    eprintln!("Connected to {} (block {})", info.chain, info.blocks);

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
    let mut total_found = 0u64;
    for height in from..=to {
        match scan_block(&client, height, args, registry.as_ref()) {
            Ok(n) => total_found += n,
            Err(e) => eprintln!("Error scanning block {height}: {e}"),
        }
    }
    eprintln!("Found {total_found} Citrea inscription(s)");
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────

fn get_auth(args: &ScanArgs) -> Auth {
    if let (Some(user), Some(pass)) = (&args.rpc_user, &args.rpc_pass) {
        Auth::UserPass(user.clone(), pass.clone())
    } else if let Some(cookie) = &args.cookie {
        Auth::CookieFile(cookie.into())
    } else {
        let home = std::env::var("HOME").unwrap_or_default();
        let cookie_path = format!("{home}/.bitcoin/testnet4/.cookie");
        if std::path::Path::new(&cookie_path).exists() {
            Auth::CookieFile(cookie_path.into())
        } else {
            eprintln!("Warning: No cookie file found at {cookie_path}");
            Auth::None
        }
    }
}

fn parse_address(s: &str) -> Result<[u8; 20], String> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 20 { return Err(format!("need 20 bytes, got {}", bytes.len())); }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

fn build_registry(args: &ScanArgs, discovered: Option<&citrea_rpc::DiscoveredContracts>) -> Option<BinstRegistry> {
    let has_any = args.deployer.is_some()
        || !args.institution.is_empty() || !args.template.is_empty()
        || !args.instance.is_empty() || discovered.is_some();
    if !has_any { return None; }

    let mut reg = BinstRegistry::new();
    if let Some(ref d) = args.deployer {
        if let Ok(addr) = parse_address(d) { reg.add_deployer(addr); }
    }
    for s in &args.institution { if let Ok(a) = parse_address(s) { reg.add_institution(a); } }
    for s in &args.template   { if let Ok(a) = parse_address(s) { reg.add_template(a); } }
    for s in &args.instance    { if let Ok(a) = parse_address(s) { reg.add_instance(a); } }
    if let Some(disc) = discovered {
        for a in &disc.institutions { reg.add_institution(*a); }
        for a in &disc.templates    { reg.add_template(*a); }
        for a in &disc.instances    { reg.add_instance(*a); }
    }
    reg.build_lookup();
    eprintln!("BINST registry: {} contracts, {} slot hashes", reg.len(), reg.lookup_table_size());
    Some(reg)
}

fn compute_wtxid(raw_tx: &[u8]) -> [u8; 32] {
    use bitcoin::hashes::{sha256d, Hash};
    let hash = sha256d::Hash::hash(raw_tx);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_ref());
    result
}

// ── Block scanning ──────────────────────────────────────────────

fn scan_block(client: &Client, height: u64, args: &ScanArgs, registry: Option<&BinstRegistry>) -> Result<u64, Box<dyn std::error::Error>> {
    let block_hash = client.get_block_hash(height)?;
    let block = client.get_block(&block_hash)?;
    let mut found = 0u64;

    for (tx_idx, tx) in block.txdata.iter().enumerate() {
        if tx_idx == 0 { continue; }
        let raw = bitcoin::consensus::serialize(tx);
        let wtxid = compute_wtxid(&raw);
        if !has_citrea_prefix(&wtxid, REVEAL_TX_PREFIX) { continue; }

        let witness: Vec<Vec<u8>> = tx.input[0].witness.to_vec();
        let Some(tapscript_bytes) = extract_tapscript(&witness) else { continue; };
        let inscription = match parse_tapscript(tapscript_bytes) {
            Ok(i) => i,
            Err(e) => { eprintln!("  Block {height} tx[{tx_idx}]: parse error: {e}"); continue; }
        };
        if let Some(filter_kind) = args.kind {
            if (inscription.kind as u16) != filter_kind { continue; }
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

// ── Text output ─────────────────────────────────────────────────

fn print_text(
    height: u64, tx_idx: usize, tx: &bitcoin::Transaction,
    wtxid: &[u8; 32], inscription: &citrea_decoder::ParsedInscription,
    registry: Option<&BinstRegistry>,
) {
    println!("Block {height} tx[{tx_idx}] — {} (wtxid: {}...)", inscription.kind, hex::encode(&wtxid[..4]));
    println!("  txid:    {}", tx.compute_txid());
    println!("  pubkey:  {}", hex::encode(inscription.tapscript_pubkey));
    println!("  body:    {} bytes", inscription.body.len());

    match inscription.decode_body() {
        Ok(DataOnDa::SequencerCommitment(sc)) => {
            println!("  ── SequencerCommitment ──");
            println!("  index: {}  l2_end: {}  merkle: {}", sc.index, sc.l2_end_block_number, hex::encode(sc.merkle_root));
        }
        Ok(DataOnDa::Complete(proof)) => {
            println!("  ── Complete Batch Proof ({} bytes compressed) ──", proof.len());
            match decode_complete_proof(&proof) {
                Ok(output) => {
                    let (start, end) = output.commitment_range();
                    println!("  l2_height: {}  roots: {}  range: {}..={}  diffs: {}",
                        output.last_l2_height(), output.state_roots().len(), start, end, output.state_diff_len());
                    print_state_diff_sample(output.state_diff(), registry);
                    print_jmt_summary(output.state_diff());
                }
                Err(e) => {
                    match decompress_proof(&proof) {
                        Ok(raw) => println!("  decompressed: {} bytes (decode failed: {e})", raw.len()),
                        Err(de) => println!("  decompress failed: {de}"),
                    }
                }
            }
        }
        Ok(DataOnDa::Aggregate(txids, _)) => println!("  ── Aggregate: {} chunks ──", txids.len()),
        Ok(DataOnDa::Chunk(data)) => println!("  ── Chunk: {} bytes ──", data.len()),
        Ok(DataOnDa::BatchProofMethodId(m)) => println!("  ── MethodId: {} bytes, {} sigs ──", m.method_id.len(), m.signatures.len()),
        Err(e) => println!("  ── Borsh error: {e} ──"),
    }
    println!();
}

fn print_state_diff_sample(state_diff: &[(Vec<u8>, Option<Vec<u8>>)], registry: Option<&BinstRegistry>) {
    if state_diff.is_empty() { return; }
    println!("  ── State Diff (first 10) ──");
    for (i, (key, value)) in state_diff.iter().take(10).enumerate() {
        let val = match value { Some(v) => format!("{} bytes", v.len()), None => "DELETED".into() };
        println!("  [{i}] key={}… ({} B) → {val}", hex::encode(&key[..std::cmp::min(8, key.len())]), key.len());
    }
    if state_diff.len() > 10 { println!("  ... and {} more", state_diff.len() - 10); }
    if let Some(reg) = registry {
        let changes = diff::map_state_diff(reg, state_diff);
        if !changes.is_empty() {
            println!("  ── BINST Changes ({}) ──", changes.len());
            for ch in &changes {
                let a = ch.contract_address.map(|a| format!("0x{}", hex::encode(a))).unwrap_or_default();
                println!("    {} {} → {} = {}", ch.contract, a, ch.field, ch.decoded);
            }
        }
    }
}

fn print_jmt_summary(state_diff: &[(Vec<u8>, Option<Vec<u8>>)]) {
    let s = jmt::summarize_diff(state_diff);
    println!("  JMT: {} storage, {} hdr, {} acct, {} idx, {} other", s.evm_storage, s.evm_header, s.evm_account, s.evm_account_idx, s.other);
}

// ── JSON output ─────────────────────────────────────────────────

fn print_json(
    height: u64, tx_idx: usize, tx: &bitcoin::Transaction,
    wtxid: &[u8; 32], inscription: &citrea_decoder::ParsedInscription,
    registry: Option<&BinstRegistry>,
) {
    let mut obj = serde_json::json!({
        "block": height, "tx_index": tx_idx,
        "txid": tx.compute_txid().to_string(), "wtxid": hex::encode(wtxid),
        "kind": format!("{}", inscription.kind),
        "pubkey": hex::encode(inscription.tapscript_pubkey),
        "body_size": inscription.body.len(),
    });
    match inscription.decode_body() {
        Ok(DataOnDa::SequencerCommitment(sc)) => {
            obj["sequencer_commitment"] = serde_json::json!({
                "index": sc.index, "l2_end_block_number": sc.l2_end_block_number,
                "merkle_root": hex::encode(sc.merkle_root),
            });
        }
        Ok(DataOnDa::Complete(proof)) => {
            let mut p = serde_json::json!({"compressed_size": proof.len()});
            if let Ok(output) = decode_complete_proof(&proof) {
                let (start, end) = output.commitment_range();
                p["last_l2_height"] = serde_json::json!(output.last_l2_height());
                p["state_roots_count"] = serde_json::json!(output.state_roots().len());
                p["commitment_range"] = serde_json::json!([start, end]);
                p["state_diff_entries"] = serde_json::json!(output.state_diff_len());
                add_json_state_diff(&mut p, output.state_diff(), registry);
            }
            obj["complete_proof"] = p;
        }
        Ok(DataOnDa::Aggregate(txids, _)) => {
            obj["aggregate"] = serde_json::json!({"chunk_count": txids.len()});
        }
        _ => {}
    }
    println!("{}", serde_json::to_string_pretty(&obj).unwrap());
}

fn add_json_state_diff(obj: &mut serde_json::Value, state_diff: &[(Vec<u8>, Option<Vec<u8>>)], registry: Option<&BinstRegistry>) {
    let sample: Vec<serde_json::Value> = state_diff.iter().take(20)
        .map(|(k, v)| serde_json::json!({"key": hex::encode(k), "value": v.as_ref().map(hex::encode)}))
        .collect();
    obj["state_diff_sample"] = serde_json::json!(sample);
    if let Some(reg) = registry {
        let changes = diff::map_state_diff(reg, state_diff);
        if !changes.is_empty() {
            let c: Vec<serde_json::Value> = changes.iter().map(|ch| serde_json::json!({
                "contract": format!("{}", ch.contract),
                "address": ch.contract_address.map(|a| format!("0x{}", hex::encode(a))),
                "field": format!("{}", ch.field), "decoded": format!("{}", ch.decoded),
            })).collect();
            obj["binst_changes"] = serde_json::json!(c);
        }
    }
    let s = jmt::summarize_diff(state_diff);
    obj["jmt_summary"] = serde_json::json!({
        "evm_storage": s.evm_storage, "evm_header": s.evm_header,
        "evm_account": s.evm_account, "evm_account_idx": s.evm_account_idx, "other": s.other,
    });
}

// ── Citrea RPC mode ─────────────────────────────────────────────

fn run_rpc_mode(citrea_url: &str, args: &ScanArgs, registry: Option<&BinstRegistry>) -> Result<(), Box<dyn std::error::Error>> {
    let client = citrea_rpc::CitreaClient::new(citrea_url);
    if let Ok(h) = client.get_last_proven_height() {
        eprintln!("Citrea proven height: {} (idx {})", h.height, h.commitment_index);
    }

    let (from, to) = if let Some(block) = args.block {
        (block, block)
    } else {
        let from = args.from.ok_or("--block or --from required in RPC mode")?;
        let to = args.to.unwrap_or(from);
        (from, to)
    };

    eprintln!("Querying blocks {from}..={to}");
    let mut total_proofs = 0u64;
    for btc_height in from..=to {
        match client.get_verified_batch_proofs(btc_height) {
            Ok(proofs) if proofs.is_empty() => {
                if args.format != "json" { eprintln!("Block {btc_height}: no proofs"); }
            }
            Ok(proofs) => {
                total_proofs += proofs.len() as u64;
                for (idx, proof) in proofs.iter().enumerate() {
                    let sd = citrea_rpc::state_diff_from_rpc(&proof.proof_output.state_diff);
                    if args.format == "json" {
                        print_rpc_json(btc_height, idx, proof, &sd, registry);
                    } else {
                        print_rpc_text(btc_height, idx, proof, &sd, registry);
                    }
                }
            }
            Err(e) => eprintln!("Error block {btc_height}: {e}"),
        }
    }
    eprintln!("Total: {total_proofs} batch proof(s)");
    Ok(())
}

fn print_rpc_text(
    h: u64, idx: usize, proof: &citrea_rpc::RpcBatchProof,
    sd: &[(Vec<u8>, Option<Vec<u8>>)], registry: Option<&BinstRegistry>,
) {
    let out = &proof.proof_output;
    println!("BTC block {h} proof[{idx}] — {} roots, {} diffs", out.state_roots.len(), sd.len());
    println!("  final_l2_hash: {}", out.final_l2_block_hash);
    print_jmt_summary(sd);
    print_state_diff_sample(sd, registry);
    println!();
}

fn print_rpc_json(
    h: u64, idx: usize, proof: &citrea_rpc::RpcBatchProof,
    sd: &[(Vec<u8>, Option<Vec<u8>>)], registry: Option<&BinstRegistry>,
) {
    let out = &proof.proof_output;
    let mut obj = serde_json::json!({
        "btc_block": h, "proof_index": idx, "source": "citrea_rpc",
        "state_roots_count": out.state_roots.len(),
        "state_diff_entries": sd.len(),
        "final_l2_block_hash": out.final_l2_block_hash,
    });
    add_json_state_diff(&mut obj, sd, registry);
    println!("{}", serde_json::to_string_pretty(&obj).unwrap());
}
