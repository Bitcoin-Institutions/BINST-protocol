//! Synchronous JSON-RPC client for EVM and Citrea-specific methods.
//!
//! Uses `ureq` (blocking HTTP). For CLI and server usage only.
//! The webapp uses its own async `fetch`-based transport via `web-sys`.

use crate::abi;
use crate::types::{L2FinalityStatus, LogEntry, TxReceipt};
use serde_json::{json, Value};

/// A configured RPC client pointing at a single endpoint.
#[derive(Debug, Clone)]
pub struct RpcClient {
    pub url: String,
}

impl RpcClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
        }
    }

    // ── Low-level JSON-RPC ────────────────────────────────────────

    /// Send a raw JSON-RPC request and return the `result` field.
    pub fn call(&self, method: &str, params: &Value) -> Result<Value, String> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        });

        let response: Value = ureq::post(&self.url)
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| format!("RPC request failed: {e}"))?
            .into_json()
            .map_err(|e| format!("RPC response parse failed: {e}"))?;

        if let Some(error) = response.get("error") {
            return Err(format!("RPC error: {error}"));
        }

        response
            .get("result")
            .cloned()
            .ok_or_else(|| "RPC response missing 'result' field".to_string())
    }

    // ── Standard EVM methods ──────────────────────────────────────

    /// `eth_blockNumber` — current L2 block height.
    pub fn block_number(&self) -> Result<u64, String> {
        let result = self.call("eth_blockNumber", &json!([]))?;
        let hex = result.as_str().ok_or("block_number: not a string")?;
        u64::from_str_radix(hex.strip_prefix("0x").unwrap_or(hex), 16)
            .map_err(|e| format!("block_number parse: {e}"))
    }

    /// `eth_call` — read-only contract call.
    /// `to` and `data` should include `0x` prefix.
    pub fn eth_call(&self, to: &str, data: &str) -> Result<String, String> {
        let result = self.call(
            "eth_call",
            &json!([{"to": to, "data": data}, "latest"]),
        )?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "eth_call: result not a string".to_string())
    }

    /// `eth_getTransactionReceipt` — fetch receipt for a mined tx.
    pub fn get_receipt(&self, tx_hash: &str) -> Result<Option<TxReceipt>, String> {
        let result = self.call("eth_getTransactionReceipt", &json!([tx_hash]))?;
        if result.is_null() {
            return Ok(None);
        }

        let status_hex = result["status"]
            .as_str()
            .unwrap_or("0x0");
        let status = status_hex.ends_with('1');

        let block_hex = result["blockNumber"]
            .as_str()
            .ok_or("receipt: missing blockNumber")?;
        let block_number =
            u64::from_str_radix(block_hex.strip_prefix("0x").unwrap_or(block_hex), 16)
                .map_err(|e| format!("receipt blockNumber: {e}"))?;

        let gas_hex = result["gasUsed"]
            .as_str()
            .unwrap_or("0x0");
        let gas_used =
            u64::from_str_radix(gas_hex.strip_prefix("0x").unwrap_or(gas_hex), 16)
                .unwrap_or(0);

        let contract_address = result["contractAddress"]
            .as_str()
            .filter(|s| !s.is_empty() && *s != "null")
            .map(|s| s.to_string());

        let logs = result["logs"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|log| LogEntry {
                        address: log["address"].as_str().unwrap_or("").to_string(),
                        topics: log["topics"]
                            .as_array()
                            .map(|t| {
                                t.iter()
                                    .map(|v| v.as_str().unwrap_or("").to_string())
                                    .collect()
                            })
                            .unwrap_or_default(),
                        data: log["data"].as_str().unwrap_or("0x").to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Some(TxReceipt {
            status,
            block_number,
            gas_used,
            contract_address,
            logs,
        }))
    }

    /// `eth_sendRawTransaction` — broadcast a signed transaction.
    pub fn send_raw_transaction(&self, signed_tx_hex: &str) -> Result<String, String> {
        let result = self.call("eth_sendRawTransaction", &json!([signed_tx_hex]))?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "send_raw_transaction: result not a string".to_string())
    }

    // ── Citrea-specific methods ───────────────────────────────────

    /// `citrea_getLastCommittedL2Height` — last L2 block committed to Bitcoin.
    pub fn get_last_committed_height(&self) -> Result<(u64, u64), String> {
        let result = self.call("citrea_getLastCommittedL2Height", &json!([]))?;
        let height = result["height"]
            .as_u64()
            .ok_or("committed: missing height")?;
        let idx = result["commitment_index"]
            .as_u64()
            .ok_or("committed: missing commitment_index")?;
        Ok((height, idx))
    }

    /// `citrea_getLastProvenL2Height` — last L2 block ZK-proven on Bitcoin.
    pub fn get_last_proven_height(&self) -> Result<(u64, u64), String> {
        let result = self.call("citrea_getLastProvenL2Height", &json!([]))?;
        let height = result["height"]
            .as_u64()
            .ok_or("proven: missing height")?;
        let idx = result["commitment_index"]
            .as_u64()
            .ok_or("proven: missing commitment_index")?;
        Ok((height, idx))
    }

    /// Get the full finality status (committed + proven boundaries).
    pub fn get_finality_status(&self) -> Result<L2FinalityStatus, String> {
        let (ch, ci) = self.get_last_committed_height()?;
        let (ph, pi) = self.get_last_proven_height()?;
        Ok(L2FinalityStatus {
            committed_height: ch,
            committed_batch_index: ci,
            proven_height: ph,
            proven_batch_index: pi,
        })
    }

    /// `ledger_getSequencerCommitmentByIndex` — get batch details.
    /// Returns `(batch_index, merkle_root, l2_end_block)`.
    pub fn get_sequencer_commitment(
        &self,
        batch_index: u64,
    ) -> Result<(u64, String, u64), String> {
        let result = self.call(
            "ledger_getSequencerCommitmentByIndex",
            &json!([batch_index]),
        )?;

        let idx_hex = result["index"]
            .as_str()
            .ok_or("batch: missing index")?;
        let idx = u64::from_str_radix(idx_hex.strip_prefix("0x").unwrap_or(idx_hex), 16)
            .map_err(|e| format!("batch index: {e}"))?;

        let merkle_root = result["merkleRoot"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let end_hex = result["l2EndBlockNumber"]
            .as_str()
            .ok_or("batch: missing l2EndBlockNumber")?;
        let end_block =
            u64::from_str_radix(end_hex.strip_prefix("0x").unwrap_or(end_hex), 16)
                .map_err(|e| format!("batch end block: {e}"))?;

        Ok((idx, merkle_root, end_block))
    }

    /// Binary-search for the batch that contains a given L2 block.
    ///
    /// `low_idx` and `high_idx` are the search bounds (inclusive).
    /// Returns `(batch_index, batch_end_block)`.
    pub fn find_batch_for_block(
        &self,
        target_block: u64,
        mut low_idx: u64,
        mut high_idx: u64,
    ) -> Result<(u64, u64), String> {
        while low_idx < high_idx {
            let mid = (low_idx + high_idx) / 2;
            let (_, _, end_block) = self.get_sequencer_commitment(mid)?;
            if end_block < target_block {
                low_idx = mid + 1;
            } else {
                high_idx = mid;
            }
        }
        let (_, _, end_block) = self.get_sequencer_commitment(low_idx)?;
        Ok((low_idx, end_block))
    }

    // ── High-level contract reads ─────────────────────────────────

    /// Read `BINSTProcess.currentStepIndex()`.
    pub fn get_current_step_index(&self, instance: &str) -> Result<u64, String> {
        let data = abi::encode_no_args(&crate::selectors::CURRENT_STEP_INDEX);
        let result = self.eth_call(instance, &data)?;
        let hex = result.strip_prefix("0x").unwrap_or(&result);
        if hex.len() < 64 {
            return Err("currentStepIndex: response too short".to_string());
        }
        abi::decode_uint256(&hex[0..64])
    }

    /// Read `BINSTProcess.totalSteps()`.
    pub fn get_total_steps(&self, instance: &str) -> Result<u64, String> {
        let data = abi::encode_no_args(&crate::selectors::TOTAL_STEPS);
        let result = self.eth_call(instance, &data)?;
        let hex = result.strip_prefix("0x").unwrap_or(&result);
        if hex.len() < 64 {
            return Err("totalSteps: response too short".to_string());
        }
        abi::decode_uint256(&hex[0..64])
    }

    /// Read `BINSTProcess.completed()`.
    pub fn is_completed(&self, instance: &str) -> Result<bool, String> {
        let data = abi::encode_no_args(&crate::selectors::COMPLETED);
        let result = self.eth_call(instance, &data)?;
        let hex = result.strip_prefix("0x").unwrap_or(&result);
        if hex.len() < 64 {
            return Err("completed: response too short".to_string());
        }
        abi::decode_bool(&hex[0..64])
    }

    /// Read `BINSTProcess.templateInscriptionId()`.
    pub fn get_template_inscription_id(&self, instance: &str) -> Result<String, String> {
        let data = abi::encode_no_args(&crate::selectors::TEMPLATE_INSCRIPTION_ID);
        let result = self.eth_call(instance, &data)?;
        let hex = result.strip_prefix("0x").unwrap_or(&result);
        if hex.len() < 128 {
            return Err("templateInscriptionId: response too short".to_string());
        }
        // ABI string: offset (32 bytes) + length (32 bytes) + data
        let offset = usize::from_str_radix(&hex[0..64], 16)
            .map_err(|e| format!("templateInscriptionId offset: {e}"))?;
        let string_start = offset * 2; // hex offset
        abi::decode_string(&hex[string_start..])
    }

    /// Read `BINSTProcess.creator()`.
    pub fn get_creator(&self, instance: &str) -> Result<String, String> {
        let data = abi::encode_no_args(&crate::selectors::CREATOR);
        let result = self.eth_call(instance, &data)?;
        let hex = result.strip_prefix("0x").unwrap_or(&result);
        if hex.len() < 64 {
            return Err("creator: response too short".to_string());
        }
        Ok(abi::decode_address(&hex[0..64]))
    }

    /// Read `BINSTProcessFactory.getInstanceCount()`.
    pub fn get_instance_count(&self, factory: &str) -> Result<u64, String> {
        let data = abi::encode_no_args(&crate::selectors::GET_INSTANCE_COUNT);
        let result = self.eth_call(factory, &data)?;
        let hex = result.strip_prefix("0x").unwrap_or(&result);
        if hex.len() < 64 {
            return Err("getInstanceCount: response too short".to_string());
        }
        abi::decode_uint256(&hex[0..64])
    }

    /// Read the tx block number from a receipt.
    pub fn get_tx_block_number(&self, tx_hash: &str) -> Result<u64, String> {
        let receipt = self
            .get_receipt(tx_hash)?
            .ok_or_else(|| format!("Receipt not found for {tx_hash}"))?;
        Ok(receipt.block_number)
    }
}
