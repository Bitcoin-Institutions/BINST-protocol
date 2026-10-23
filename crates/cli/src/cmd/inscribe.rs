//! `binst inscribe` — Inscribe a BINST entity on Bitcoin via Mempool.space API.
//!
//! No local Bitcoin node required. Builds commit+reveal PSBTs, signs them
//! locally with the provided private key, and broadcasts via Mempool.space.

use binst_btc::mempool::MempoolClient;
use binst_btc::txbuilder::build_commit_reveal;
use binst_btc::types::BtcNetwork;
use binst_inscription::BinstEntity;
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{self, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{self, LeafVersion, TaprootSpendInfo};
use bitcoin::{Address, Network, ScriptBuf, TapSighashType, TxOut, Witness};
use clap::Args;
use std::str::FromStr;

#[derive(Args, Debug)]
pub struct InscribeArgs {
    /// Path to JSON file containing the BINST entity body.
    #[arg(long)]
    pub file: String,

    /// Private key (WIF format, e.g. cVt4o7BGAig1UXywgGS...  or hex).
    #[arg(long)]
    pub private_key: String,

    /// Fee rate in sat/vB (0 = auto from mempool.space).
    #[arg(long, default_value = "0")]
    pub fee_rate: u64,

    /// Parent inscription ID for provenance linking (e.g. "abcdef...i0").
    #[arg(long)]
    pub parent: Option<String>,

    /// Bitcoin network.
    #[arg(long, default_value = "testnet4")]
    pub network: String,

    /// Output format: "text" or "json".
    #[arg(long, default_value = "text")]
    pub format: String,
}

pub fn run(args: &InscribeArgs) -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();

    // ── Parse network ────────────────────────────────────────────
    let btc_network = match args.network.as_str() {
        "testnet4" => BtcNetwork::Testnet4,
        "signet" => BtcNetwork::Signet,
        "mainnet" | "bitcoin" => BtcNetwork::Mainnet,
        other => return Err(format!("Unknown network: {other}").into()),
    };
    let network = btc_network.to_bitcoin_network();

    // ── Parse private key ────────────────────────────────────────
    let keypair = parse_private_key(&args.private_key, network, &secp)?;
    let (x_only_pubkey, _parity) = keypair.x_only_public_key();

    // ── Derive address ───────────────────────────────────────────
    let address = Address::p2tr(&secp, x_only_pubkey, None, network);
    eprintln!("Address: {address}");

    // ── Read entity JSON ─────────────────────────────────────────
    let json_str = std::fs::read_to_string(&args.file)
        .map_err(|e| format!("Read {}: {e}", args.file))?;
    let entity: BinstEntity = serde_json::from_str(&json_str)
        .map_err(|e| format!("Parse entity JSON: {e}"))?;
    eprintln!("Entity: {} (type: {})", entity_name(&entity), entity_type(&entity));

    // ── Fetch UTXOs ──────────────────────────────────────────────
    let mempool = MempoolClient::new(btc_network);
    let addr_str = address.to_string();
    let mut utxos = mempool.fetch_utxos(&addr_str)?;
    eprintln!("UTXOs found: {}", utxos.len());

    if utxos.is_empty() {
        return Err(format!("No UTXOs at {address}. Fund it first.").into());
    }

    // Fill in script_pubkey (mempool API doesn't return it)
    let addr_script = address.script_pubkey();
    for u in &mut utxos {
        u.script_pubkey = addr_script.clone();
    }

    // ── Fee rate ─────────────────────────────────────────────────
    let fee_rate = if args.fee_rate == 0 {
        let (_, _, hour, _) = mempool.get_fee_rates()?;
        eprintln!("Auto fee rate: {hour} sat/vB (1-hour target)");
        hour
    } else {
        args.fee_rate
    };

    // ── Build commit+reveal ──────────────────────────────────────
    let plan = build_commit_reveal(
        &entity,
        &x_only_pubkey,
        &utxos,
        fee_rate,
        &address,
        network,
        args.parent.as_deref(),
        None, // TODO: parent UTXO fetch for child inscriptions
    )?;

    eprintln!(
        "Plan: commit {} sats, reveal {} sats, total fee {} sats",
        plan.commit_tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>(),
        plan.reveal_tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>(),
        plan.estimated_fee,
    );

    // ── Sign commit tx (key-path P2TR spend) ─────────────────────
    let signed_commit = sign_commit_tx(
        &plan.commit_tx,
        &plan.commit_utxos.iter().map(|u| TxOut {
            value: u.amount,
            script_pubkey: u.script_pubkey.clone(),
        }).collect::<Vec<_>>(),
        &keypair,
        &secp,
    )?;

    // ── Sign reveal tx (Tapscript spend for input 0) ─────────────
    let commit_txout = TxOut {
        value: plan.commit_tx.output[0].value,
        script_pubkey: plan.commit_tx.output[0].script_pubkey.clone(),
    };
    let signed_reveal = sign_reveal_tx(
        &plan.reveal_tx,
        &commit_txout,
        &plan.inscription_script,
        &plan.taproot_spend_info,
        &keypair,
        &secp,
    )?;

    // ── Broadcast ────────────────────────────────────────────────
    eprintln!("Broadcasting commit tx...");
    let commit_hex = bitcoin::consensus::encode::serialize_hex(&signed_commit);
    let commit_txid = mempool.broadcast(&commit_hex)?;
    eprintln!("Commit txid: {commit_txid}");

    eprintln!("Broadcasting reveal tx...");
    let reveal_hex = bitcoin::consensus::encode::serialize_hex(&signed_reveal);
    let reveal_txid = mempool.broadcast(&reveal_hex)?;
    let inscription_id = format!("{reveal_txid}i0");

    // ── Output ───────────────────────────────────────────────────
    if args.format == "json" {
        let output = serde_json::json!({
            "commit_txid": commit_txid,
            "reveal_txid": reveal_txid,
            "inscription_id": inscription_id,
            "address": addr_str,
            "fee_rate": fee_rate,
            "estimated_fee": plan.estimated_fee,
            "network": args.network,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("✓ Inscription broadcast successfully!");
        println!("  Commit tx:      {commit_txid}");
        println!("  Reveal tx:      {reveal_txid}");
        println!("  Inscription ID: {inscription_id}");
        println!("  Explorer:       {}/tx/{reveal_txid}", btc_network.mempool_api_base().replace("/api", ""));
    }

    Ok(())
}

/// Parse a private key from WIF or hex format.
fn parse_private_key(
    input: &str,
    _network: Network,
    secp: &Secp256k1<secp256k1::All>,
) -> Result<Keypair, Box<dyn std::error::Error>> {
    // Try WIF first
    if let Ok(privkey) = bitcoin::PrivateKey::from_str(input) {
        return Ok(Keypair::from_secret_key(secp, &privkey.inner));
    }
    // Try raw hex (32 bytes = 64 hex chars)
    let hex_clean = input.strip_prefix("0x").unwrap_or(input);
    if hex_clean.len() == 64 {
        let bytes = hex::decode(hex_clean)?;
        let secret = secp256k1::SecretKey::from_slice(&bytes)?;
        return Ok(Keypair::from_secret_key(secp, &secret));
    }
    Err(format!("Cannot parse private key. Use WIF (cVt4o...) or 64-char hex.").into())
}

/// Sign all inputs of the commit tx (P2TR key-path spends).
fn sign_commit_tx(
    unsigned: &bitcoin::Transaction,
    prevouts: &[TxOut],
    keypair: &Keypair,
    secp: &Secp256k1<secp256k1::All>,
) -> Result<bitcoin::Transaction, String> {
    let mut tx = unsigned.clone();
    let all_prevouts = Prevouts::All(prevouts);

    for i in 0..tx.input.len() {
        let mut sighash_cache = SighashCache::new(&tx);
        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(i, &all_prevouts, TapSighashType::Default)
            .map_err(|e| format!("commit sighash[{i}]: {e}"))?;

        let msg = Message::from_digest(sighash.to_byte_array());
        // Tweak the keypair for key-path spending (BIP-341)
        let tweaked = keypair.tap_tweak(secp, None);
        let sig = secp.sign_schnorr(&msg, &tweaked.to_keypair());
        let schnorr_sig = taproot::Signature {
            signature: sig,
            sighash_type: TapSighashType::Default,
        };

        tx.input[i].witness = Witness::from_slice(&[schnorr_sig.to_vec()]);
    }

    Ok(tx)
}

/// Sign the reveal tx:
///   Input 0: Tapscript spend (inscription script leaf)
///   Input 1+: key-path spend (parent UTXO, if any)
fn sign_reveal_tx(
    unsigned: &bitcoin::Transaction,
    commit_txout: &TxOut,
    inscription_script: &ScriptBuf,
    taproot_spend_info: &TaprootSpendInfo,
    keypair: &Keypair,
    secp: &Secp256k1<secp256k1::All>,
) -> Result<bitcoin::Transaction, String> {
    let mut tx = unsigned.clone();

    // Build prevouts list
    let prevout_list = vec![commit_txout.clone()];
    // TODO: add parent UTXO TxOut here when parent spending is supported

    let all_prevouts = Prevouts::All(&prevout_list);

    // Input 0: Tapscript spend
    {
        let leaf_hash = taproot::TapLeafHash::from_script(inscription_script, LeafVersion::TapScript);
        let mut sighash_cache = SighashCache::new(&tx);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(
                0,
                &all_prevouts,
                leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|e| format!("reveal sighash[0]: {e}"))?;

        let msg = Message::from_digest(sighash.to_byte_array());
        // Script-path: sign with raw keypair (no tweak)
        let sig = secp.sign_schnorr(&msg, keypair);
        let schnorr_sig = taproot::Signature {
            signature: sig,
            sighash_type: TapSighashType::Default,
        };

        // Witness: [signature, script, control_block]
        let control_block = taproot_spend_info
            .control_block(&(inscription_script.clone(), LeafVersion::TapScript))
            .ok_or("No control block for inscription script")?;

        let sig_bytes = schnorr_sig.to_vec();
        let script_bytes = inscription_script.as_bytes().to_vec();
        let cb_bytes = control_block.serialize();

        let mut witness = Witness::new();
        witness.push(&sig_bytes);
        witness.push(&script_bytes);
        witness.push(&cb_bytes);
        tx.input[0].witness = witness;
    }

    // TODO: Input 1 (parent UTXO key-path spend) when parent spending is added

    Ok(tx)
}

fn entity_name(entity: &BinstEntity) -> &str {
    match entity {
        BinstEntity::Institution(i) => &i.name,
        BinstEntity::ProcessTemplate(p) => &p.name,
        BinstEntity::ProcessInstance(_) => "process_instance",
        BinstEntity::StepExecution(_) => "step_execution",
        BinstEntity::StateDigest(_) => "state_digest",
    }
}

fn entity_type(entity: &BinstEntity) -> &str {
    match entity {
        BinstEntity::Institution(_) => "institution",
        BinstEntity::ProcessTemplate(_) => "process_template",
        BinstEntity::ProcessInstance(_) => "process_instance",
        BinstEntity::StepExecution(_) => "step_execution",
        BinstEntity::StateDigest(_) => "state_digest",
    }
}
