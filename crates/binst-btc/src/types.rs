//! Shared types for Bitcoin inscription operations.

use bitcoin::{Amount, OutPoint, ScriptBuf};

/// A spendable UTXO.
#[derive(Debug, Clone)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub amount: Amount,
    pub script_pubkey: ScriptBuf,
}

/// Result of building a commit+reveal pair.
#[derive(Debug, Clone)]
pub struct InscriptionPlan {
    /// Unsigned commit transaction.
    pub commit_tx: bitcoin::Transaction,
    /// Unsigned reveal transaction.
    pub reveal_tx: bitcoin::Transaction,
    /// Taproot spend info for the reveal witness.
    pub taproot_spend_info: bitcoin::taproot::TaprootSpendInfo,
    /// The inscription script (Tapscript leaf).
    pub inscription_script: ScriptBuf,
    /// Estimated total fee in sats.
    pub estimated_fee: u64,
    /// UTXOs selected for commit inputs.
    pub commit_utxos: Vec<Utxo>,
    /// Optional parent UTXO (second input of reveal tx).
    pub parent_utxo: Option<Utxo>,
}

/// Result of a successful inscription broadcast.
#[derive(Debug, Clone)]
pub struct InscribeResult {
    /// Commit transaction ID.
    pub commit_txid: String,
    /// Reveal transaction ID.
    pub reveal_txid: String,
    /// Inscription ID (reveal_txid:0 in Ordinals format).
    pub inscription_id: String,
    /// The reveal UTXO (output 0) — for chaining as parent in child inscriptions.
    pub reveal_utxo: Utxo,
}

/// Confirmation status of a broadcast transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmationStatus {
    /// Transaction is in the mempool.
    Mempool,
    /// Transaction has N confirmations.
    Confirmed { confirmations: u32 },
    /// Transaction was not found (may have been dropped).
    NotFound,
}

/// Bitcoin network configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtcNetwork {
    Testnet4,
    Signet,
    Mainnet,
}

impl BtcNetwork {
    /// Mempool.space API base URL for this network.
    pub fn mempool_api_base(&self) -> &'static str {
        match self {
            BtcNetwork::Testnet4 => "https://mempool.space/testnet4/api",
            BtcNetwork::Signet => "https://mempool.space/signet/api",
            BtcNetwork::Mainnet => "https://mempool.space/api",
        }
    }

    /// Convert to `bitcoin::Network`.
    pub fn to_bitcoin_network(&self) -> bitcoin::Network {
        match self {
            BtcNetwork::Testnet4 => bitcoin::Network::Testnet4,
            BtcNetwork::Signet => bitcoin::Network::Signet,
            BtcNetwork::Mainnet => bitcoin::Network::Bitcoin,
        }
    }
}
