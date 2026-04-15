//! Commit+reveal PSBT construction for Ordinals inscriptions.
//!
//! Ported from `webapp/binst-pilot-webapp/src/txbuilder.rs`.

use bitcoin::key::{UntweakedPublicKey, XOnlyPublicKey};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{
    transaction, Address, Amount, Network, OutPoint, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Witness,
};

use binst_inscription::BinstEntity;

use crate::script::build_inscription_script;
use crate::types::{InscriptionPlan, Utxo};

/// Dust limit for Taproot outputs (546 sats).
const DUST_LIMIT: u64 = 546;

/// NUMS point — provably unspendable internal key (BIP-341 recommended).
const NUMS_POINT_HEX: &str =
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/// Parse the NUMS internal key.
fn nums_internal_key() -> Result<UntweakedPublicKey, String> {
    let bytes = hex::decode(NUMS_POINT_HEX)
        .map_err(|e| format!("NUMS hex decode: {e}"))?;
    XOnlyPublicKey::from_slice(&bytes)
        .map_err(|e| format!("NUMS key parse: {e}"))
}

/// Build a commit+reveal inscription pair.
///
/// Returns an `InscriptionPlan` containing both unsigned transactions,
/// the taproot spend info, and the inscription script.
///
/// # Arguments
/// * `entity` — the BINST entity to inscribe (Institution, ProcessTemplate, etc.)
/// * `admin_pubkey` — the x-only public key of the admin (used in the Tapscript)
/// * `utxos` — available UTXOs for funding
/// * `fee_rate` — fee rate in sat/vB
/// * `change_address` — where to send inscription sat + change
/// * `network` — Bitcoin network
/// * `parent_inscription_id` — optional parent inscription ID for provenance linking
/// * `parent_utxo` — optional parent UTXO to spend as reveal input 1
pub fn build_commit_reveal(
    entity: &BinstEntity,
    admin_pubkey: &XOnlyPublicKey,
    utxos: &[Utxo],
    fee_rate: u64,
    change_address: &Address,
    network: Network,
    parent_inscription_id: Option<&str>,
    parent_utxo: Option<&Utxo>,
) -> Result<InscriptionPlan, String> {
    // 1. Build the inscription script
    let inscription_script =
        build_inscription_script(entity, admin_pubkey, parent_inscription_id)?;

    // 2. Build the Taproot tree with the inscription script as the only leaf
    let secp = Secp256k1::new();
    let internal_key = nums_internal_key()?;
    let taproot = TaprootBuilder::new()
        .add_leaf(0, inscription_script.clone())
        .map_err(|e| format!("TaprootBuilder leaf: {e}"))?
        .finalize(&secp, internal_key)
        .map_err(|_| "TaprootBuilder finalize failed".to_string())?;

    let commit_address =
        Address::p2tr_tweaked(taproot.output_key(), network);

    // 3. Estimate sizes and fees
    // Commit: ~111 vB (1 input, 2 outputs typical)
    let commit_vsize: u64 = 111;
    // Reveal: ~200 vB base + inscription script weight / 4
    let script_vsize = (inscription_script.len() as u64 + 3) / 4;
    let mut reveal_vsize: u64 = 200 + script_vsize;

    // If parent UTXO is included, add ~101 vB for the extra input+output
    if parent_utxo.is_some() {
        reveal_vsize += 101;
    }

    let commit_fee = commit_vsize * fee_rate;
    let reveal_fee = reveal_vsize * fee_rate;
    let total_fee = commit_fee + reveal_fee;

    // Amount needed in the commit output: reveal fee + dust for inscription output
    let commit_output_amount = reveal_fee + DUST_LIMIT;

    // 4. Coin selection — filter dust UTXOs, pick enough for commit + fee
    let mut selected: Vec<Utxo> = Vec::new();
    let mut selected_total: u64 = 0;
    let needed = commit_output_amount + commit_fee;

    for utxo in utxos {
        if utxo.amount.to_sat() <= DUST_LIMIT {
            continue; // skip inscription UTXOs / dust
        }
        selected.push(utxo.clone());
        selected_total += utxo.amount.to_sat();
        if selected_total >= needed {
            break;
        }
    }

    if selected_total < needed {
        return Err(format!(
            "Insufficient funds: have {selected_total} sats, need {needed} sats"
        ));
    }

    // 5. Build the commit transaction
    let commit_inputs: Vec<TxIn> = selected
        .iter()
        .map(|u| TxIn {
            previous_output: u.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        })
        .collect();

    let mut commit_outputs = vec![TxOut {
        value: Amount::from_sat(commit_output_amount),
        script_pubkey: commit_address.script_pubkey(),
    }];

    let change = selected_total - commit_output_amount - commit_fee;
    if change > DUST_LIMIT {
        commit_outputs.push(TxOut {
            value: Amount::from_sat(change),
            script_pubkey: change_address.script_pubkey(),
        });
    }

    let commit_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: commit_inputs,
        output: commit_outputs,
    };

    // 6. Build the reveal transaction
    // Input 0: commit output (the Tapscript lockbox)
    let mut reveal_inputs = vec![TxIn {
        previous_output: OutPoint::new(commit_tx.compute_txid(), 0),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    }];

    // Output 0: inscription sat → change_address (discoverable by wallet)
    let mut reveal_outputs = vec![TxOut {
        value: Amount::from_sat(DUST_LIMIT),
        script_pubkey: change_address.script_pubkey(),
    }];

    // Input 1 + Output 1: parent UTXO pass-through (if present)
    if let Some(parent) = parent_utxo {
        reveal_inputs.push(TxIn {
            previous_output: parent.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        });
        reveal_outputs.push(TxOut {
            value: Amount::from_sat(DUST_LIMIT),
            script_pubkey: change_address.script_pubkey(),
        });
    }

    let reveal_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: reveal_inputs,
        output: reveal_outputs,
    };

    Ok(InscriptionPlan {
        commit_tx,
        reveal_tx,
        taproot_spend_info: taproot,
        inscription_script,
        estimated_fee: total_fee,
        commit_utxos: selected,
        parent_utxo: parent_utxo.cloned(),
    })
}

/// Convert an unsigned commit transaction to a PSBT.
pub fn commit_to_psbt(plan: &InscriptionPlan) -> Result<Psbt, String> {
    let mut psbt = Psbt::from_unsigned_tx(plan.commit_tx.clone())
        .map_err(|e| format!("commit PSBT: {e}"))?;

    // Populate witness_utxo for each input
    for (i, utxo) in plan.commit_utxos.iter().enumerate() {
        if i < psbt.inputs.len() {
            psbt.inputs[i].witness_utxo = Some(TxOut {
                value: utxo.amount,
                script_pubkey: utxo.script_pubkey.clone(),
            });
        }
    }

    Ok(psbt)
}

/// Serialize a PSBT to base64.
pub fn psbt_to_base64(psbt: &Psbt) -> String {
    use bitcoin::base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.encode(psbt.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nums_key_parses() {
        let key = nums_internal_key().unwrap();
        assert_eq!(hex::encode(key.serialize()), NUMS_POINT_HEX);
    }
}
