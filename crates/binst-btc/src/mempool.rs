//! Mempool.space API client for UTXO queries and transaction broadcast.
//!
//! Synchronous (blocking) — for CLI usage only.

use crate::types::{BtcNetwork, ConfirmationStatus, Utxo};
use bitcoin::{Amount, OutPoint, ScriptBuf, Txid};
use serde_json::Value;

/// A configured Mempool.space API client.
#[derive(Debug, Clone)]
pub struct MempoolClient {
    base_url: String,
}

impl MempoolClient {
    /// Create a client for the given network.
    pub fn new(network: BtcNetwork) -> Self {
        Self {
            base_url: network.mempool_api_base().to_string(),
        }
    }

    /// Create a client with a custom base URL (e.g. local mempool instance).
    pub fn with_url(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Fetch UTXOs for an address (confirmed + unconfirmed).
    pub fn fetch_utxos(&self, address: &str) -> Result<Vec<Utxo>, String> {
        let url = format!("{}/address/{}/utxo", self.base_url, address);
        let response: Value = ureq::get(&url)
            .call()
            .map_err(|e| format!("fetch_utxos: {e}"))?
            .into_json()
            .map_err(|e| format!("fetch_utxos parse: {e}"))?;

        let arr = response
            .as_array()
            .ok_or("fetch_utxos: response not an array")?;

        let mut utxos = Vec::with_capacity(arr.len());
        for item in arr {
            let txid_str = item["txid"]
                .as_str()
                .ok_or("UTXO missing txid")?;
            let txid: Txid = txid_str
                .parse()
                .map_err(|e| format!("UTXO txid parse: {e}"))?;
            let vout = item["vout"]
                .as_u64()
                .ok_or("UTXO missing vout")? as u32;
            let value = item["value"]
                .as_u64()
                .ok_or("UTXO missing value")?;

            utxos.push(Utxo {
                outpoint: OutPoint::new(txid, vout),
                amount: Amount::from_sat(value),
                // Mempool API doesn't return scriptPubkey — caller must derive from address
                script_pubkey: ScriptBuf::new(),
            });
        }

        Ok(utxos)
    }

    /// Broadcast a raw transaction (hex-encoded).
    pub fn broadcast(&self, tx_hex: &str) -> Result<String, String> {
        let url = format!("{}/tx", self.base_url);
        let response = ureq::post(&url)
            .set("Content-Type", "text/plain")
            .send_string(tx_hex)
            .map_err(|e| format!("broadcast: {e}"))?;
        let txid = response
            .into_string()
            .map_err(|e| format!("broadcast response: {e}"))?;
        Ok(txid.trim().to_string())
    }

    /// Check the confirmation status of a transaction.
    pub fn get_tx_status(&self, txid: &str) -> Result<ConfirmationStatus, String> {
        let url = format!("{}/tx/{}/status", self.base_url, txid);
        let response: Value = ureq::get(&url)
            .call()
            .map_err(|e| format!("get_tx_status: {e}"))?
            .into_json()
            .map_err(|e| format!("get_tx_status parse: {e}"))?;

        let confirmed = response["confirmed"].as_bool().unwrap_or(false);
        if !confirmed {
            return Ok(ConfirmationStatus::Mempool);
        }

        let block_height = response["block_height"]
            .as_u64()
            .ok_or("tx status: missing block_height")?;

        // Get current tip to compute confirmations
        let tip_url = format!("{}/blocks/tip/height", self.base_url);
        let tip: u64 = ureq::get(&tip_url)
            .call()
            .map_err(|e| format!("tip height: {e}"))?
            .into_string()
            .map_err(|e| format!("tip parse: {e}"))?
            .trim()
            .parse()
            .map_err(|e| format!("tip number: {e}"))?;

        let confirmations = (tip - block_height + 1) as u32;
        Ok(ConfirmationStatus::Confirmed { confirmations })
    }

    /// Get the current recommended fee rates.
    /// Returns `(fastest, half_hour, hour, economy)` in sat/vB.
    pub fn get_fee_rates(&self) -> Result<(u64, u64, u64, u64), String> {
        let url = format!("{}/v1/fees/recommended", self.base_url);
        let response: Value = ureq::get(&url)
            .call()
            .map_err(|e| format!("fee_rates: {e}"))?
            .into_json()
            .map_err(|e| format!("fee_rates parse: {e}"))?;

        Ok((
            response["fastestFee"].as_u64().unwrap_or(10),
            response["halfHourFee"].as_u64().unwrap_or(8),
            response["hourFee"].as_u64().unwrap_or(5),
            response["economyFee"].as_u64().unwrap_or(2),
        ))
    }
}
