//! Citrea L2 RPC client — queries batch proofs + state diffs directly from a
//! Citrea full node, bypassing Bitcoin block scanning entirely.
//!
//! Key RPCs:
//!   • `ledger_getVerifiedBatchProofsBySlotHeight(btcBlockHeight)` — returns
//!     proven batch proofs (with state diffs) anchored to a Bitcoin block.
//!   • `ledger_getSequencerCommitmentsOnSlotByNumber(btcBlockHeight)` — returns
//!     sequencer commitments (merkle root, L2 end block).
//!   • `citrea_getLastProvenL2Height` / `citrea_getLastCommittedL2Height`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── JSON-RPC types ──────────────────────────────────────────────

#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'a str,
    method: &'a str,
    params: Value,
    id: u64,
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    result: Option<Value>,
    error: Option<Value>,
    #[allow(dead_code)]
    id: Option<u64>,
}

// ── Deserialized Citrea types ───────────────────────────────────

/// Proof output as returned by `ledger_getVerifiedBatchProofsBySlotHeight`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBatchProof {
    pub proof_output: RpcProofOutput,
    // `proof` field omitted — we only need the decoded output
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcProofOutput {
    pub state_roots: Vec<String>,
    pub final_l2_block_hash: String,
    /// Hex-keyed map: `"0x452f..." → "0xabcd..."`
    pub state_diff: serde_json::Map<String, Value>,
}

/// Sequencer commitment as returned by `ledger_getSequencerCommitmentsOnSlotByNumber`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct RpcSequencerCommitment {
    pub merkle_root: String,
    pub index: String,
    pub l2_end_block_number: String,
}

/// Result of `citrea_getLastProvenL2Height`.
#[derive(Debug, Clone, Deserialize)]
pub struct ProvenHeight {
    pub height: u64,
    pub commitment_index: u64,
}

// ── Client ──────────────────────────────────────────────────────

/// Minimal synchronous Citrea RPC client.
pub struct CitreaClient {
    url: String,
    next_id: std::cell::Cell<u64>,
}

impl CitreaClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            next_id: std::cell::Cell::new(1),
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, Box<dyn std::error::Error>> {
        let id = self.next_id.get();
        self.next_id.set(id + 1);

        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id,
        };

        let resp: JsonRpcResponse = ureq::post(&self.url)
            .set("Content-Type", "application/json")
            .send_json(serde_json::to_value(&req)?)?
            .into_json()?;

        if let Some(err) = resp.error {
            return Err(format!("RPC error: {err}").into());
        }

        // Return Value::Null instead of Err when result is null —
        // some RPCs legitimately return null (e.g. no proofs for a block).
        Ok(resp.result.unwrap_or(Value::Null))
    }

    // ── High-level methods ──────────────────────────────────────

    /// Get verified batch proofs for a given Bitcoin block height.
    /// Returns an empty vec when the RPC returns null (no proofs for that block).
    pub fn get_verified_batch_proofs(
        &self,
        btc_height: u64,
    ) -> Result<Vec<RpcBatchProof>, Box<dyn std::error::Error>> {
        let val = self.call(
            "ledger_getVerifiedBatchProofsBySlotHeight",
            serde_json::json!([btc_height]),
        )?;
        if val.is_null() {
            return Ok(Vec::new());
        }
        let proofs: Vec<RpcBatchProof> = serde_json::from_value(val)?;
        Ok(proofs)
    }

    /// Get sequencer commitments for a given Bitcoin block height.
    #[allow(dead_code)]
    pub fn get_sequencer_commitments(
        &self,
        btc_height: u64,
    ) -> Result<Vec<RpcSequencerCommitment>, Box<dyn std::error::Error>> {
        let val = self.call(
            "ledger_getSequencerCommitmentsOnSlotByNumber",
            serde_json::json!([btc_height]),
        )?;
        let commits: Vec<RpcSequencerCommitment> = serde_json::from_value(val)?;
        Ok(commits)
    }

    /// Get the last proven L2 height.
    pub fn get_last_proven_height(
        &self,
    ) -> Result<ProvenHeight, Box<dyn std::error::Error>> {
        let val = self.call("citrea_getLastProvenL2Height", serde_json::json!([]))?;
        let h: ProvenHeight = serde_json::from_value(val)?;
        Ok(h)
    }

    /// Get the last committed L2 height.
    #[allow(dead_code)]
    pub fn get_last_committed_height(&self) -> Result<u64, Box<dyn std::error::Error>> {
        let val = self.call("citrea_getLastCommittedL2Height", serde_json::json!([]))?;
        Ok(val.as_u64().unwrap_or(0))
    }

    // ── EVM view calls (for BINST discovery) ────────────────────

    /// Call a Solidity view function that returns `address[]`.
    /// `selector` is the 4-byte function selector (e.g. keccak256("getInstitutions()")[:4]).
    fn call_address_array(
        &self,
        contract: &str,
        selector: [u8; 4],
    ) -> Result<Vec<[u8; 20]>, Box<dyn std::error::Error>> {
        let calldata = format!("0x{}", hex::encode(selector));
        let val = self.call(
            "eth_call",
            serde_json::json!([
                { "to": contract, "data": calldata },
                "latest"
            ]),
        )?;
        let hex_str = val
            .as_str()
            .ok_or("eth_call returned non-string")?;
        let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))?;
        decode_address_array(&bytes)
    }

    /// Discover all BINST contract addresses from a deployer contract.
    ///
    /// Discovery chain:
    ///   1. `deployer.getInstitutions()` → Institution addresses
    ///   2. For each Institution: `institution.getProcesses()` → ProcessTemplate addresses
    ///   3. Also: `deployer.getDeployedProcesses()` → standalone ProcessTemplate addresses
    ///   4. For each ProcessTemplate: `template.getAllInstances()` → ProcessInstance addresses
    pub fn discover_binst_contracts(
        &self,
        deployer_addr: &str,
    ) -> Result<DiscoveredContracts, Box<dyn std::error::Error>> {
        // 1. Get institutions from deployer
        let institutions =
            self.call_address_array(deployer_addr, SELECTOR_GET_INSTITUTIONS)?;

        // 2. Get templates from each institution
        let mut templates = Vec::new();
        for inst in &institutions {
            let inst_addr = format!("0x{}", hex::encode(inst));
            match self.call_address_array(&inst_addr, SELECTOR_GET_PROCESSES) {
                Ok(addrs) => templates.extend(addrs),
                Err(e) => eprintln!(
                    "Warning: getProcesses() failed for institution {inst_addr}: {e}"
                ),
            }
        }

        // 3. Also get standalone templates from deployer
        match self.call_address_array(deployer_addr, SELECTOR_GET_DEPLOYED_PROCESSES) {
            Ok(addrs) => {
                for addr in addrs {
                    if !templates.contains(&addr) {
                        templates.push(addr);
                    }
                }
            }
            Err(e) => eprintln!("Warning: getDeployedProcesses() failed: {e}"),
        }

        // 4. For each template, get instances
        let mut instances = Vec::new();
        for tpl in &templates {
            let tpl_addr = format!("0x{}", hex::encode(tpl));
            match self.call_address_array(&tpl_addr, SELECTOR_GET_ALL_INSTANCES) {
                Ok(addrs) => instances.extend(addrs),
                Err(e) => eprintln!(
                    "Warning: getAllInstances() failed for template {tpl_addr}: {e}"
                ),
            }
        }

        Ok(DiscoveredContracts {
            institutions,
            templates,
            instances,
        })
    }
}

/// Pre-computed function selectors (first 4 bytes of keccak256 of the signature).
const SELECTOR_GET_INSTITUTIONS: [u8; 4] = [0x87, 0x6d, 0x03, 0x2e]; // getInstitutions()
const SELECTOR_GET_DEPLOYED_PROCESSES: [u8; 4] = [0xe1, 0x7e, 0x0d, 0xce]; // getDeployedProcesses()
const SELECTOR_GET_ALL_INSTANCES: [u8; 4] = [0x52, 0xc2, 0x28, 0xe3]; // getAllInstances()
const SELECTOR_GET_PROCESSES: [u8; 4] = [0x6e, 0x52, 0xb2, 0x39]; // getProcesses()

/// Contracts discovered via on-chain queries to the deployer.
#[derive(Debug, Clone)]
pub struct DiscoveredContracts {
    pub institutions: Vec<[u8; 20]>,
    pub templates: Vec<[u8; 20]>,
    pub instances: Vec<[u8; 20]>,
}

/// Decode ABI-encoded `address[]` return data.
///
/// Layout: `[offset(32)] [length(32)] [addr0_padded(32)] [addr1_padded(32)] ...`
fn decode_address_array(data: &[u8]) -> Result<Vec<[u8; 20]>, Box<dyn std::error::Error>> {
    if data.len() < 64 {
        return Ok(Vec::new());
    }
    // First 32 bytes = offset to array data (always 0x20 for a single return)
    // Next 32 bytes at that offset = array length
    let offset = u256_to_usize(&data[0..32]);
    if offset + 32 > data.len() {
        return Err("ABI offset out of bounds".into());
    }
    let length = u256_to_usize(&data[offset..offset + 32]);
    let mut addrs = Vec::with_capacity(length);
    for i in 0..length {
        let start = offset + 32 + i * 32;
        if start + 32 > data.len() {
            break;
        }
        // Address is in the last 20 bytes of the 32-byte word
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&data[start + 12..start + 32]);
        addrs.push(addr);
    }
    Ok(addrs)
}

/// Read a big-endian U256 as usize (only uses last 8 bytes).
fn u256_to_usize(word: &[u8]) -> usize {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&word[24..32]);
    u64::from_be_bytes(buf) as usize
}

// ── State diff conversion ───────────────────────────────────────

/// Convert an RPC `stateDiff` (hex-keyed JSON map) into the same
/// `Vec<(Vec<u8>, Option<Vec<u8>>)>` format used by the batch proof decoder.
///
/// This lets us feed RPC-sourced state diffs straight into `map_state_diff()`
/// and `jmt::summarize_diff()`.
pub fn state_diff_from_rpc(
    map: &serde_json::Map<String, Value>,
) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    let mut entries = Vec::with_capacity(map.len());
    for (key_hex, val_json) in map {
        let key_hex = key_hex.strip_prefix("0x").unwrap_or(key_hex);
        let Ok(key_bytes) = hex::decode(key_hex) else {
            continue;
        };
        let value = match val_json {
            Value::Null => None,
            Value::String(s) => {
                let s = s.strip_prefix("0x").unwrap_or(s);
                hex::decode(s).ok()
            }
            _ => None,
        };
        entries.push((key_bytes, value));
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_diff_from_rpc_basic() {
        let mut map = serde_json::Map::new();
        map.insert(
            "0x452f482f0000000000000000".into(),
            Value::String("0xabcdef".into()),
        );
        map.insert(
            "0x452f732f1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".into(),
            Value::String("0x01".into()),
        );
        map.insert(
            "0xdead".into(),
            Value::Null,
        );

        let entries = state_diff_from_rpc(&map);
        assert_eq!(entries.len(), 3);

        // Find the header entry
        let header = entries
            .iter()
            .find(|(k, _)| k.starts_with(&[0x45, 0x2f, 0x48, 0x2f]))
            .unwrap();
        assert!(header.1.is_some());
        assert_eq!(header.1.as_ref().unwrap(), &[0xab, 0xcd, 0xef]);

        // Find the deleted entry
        let deleted = entries
            .iter()
            .find(|(k, _)| k == &[0xde, 0xad])
            .unwrap();
        assert!(deleted.1.is_none());
    }

    #[test]
    fn state_diff_from_rpc_no_prefix() {
        let mut map = serde_json::Map::new();
        map.insert(
            "aabb".into(),
            Value::String("ccdd".into()),
        );
        let entries = state_diff_from_rpc(&map);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, vec![0xaa, 0xbb]);
        assert_eq!(entries[0].1.as_ref().unwrap(), &[0xcc, 0xdd]);
    }

    #[test]
    fn decode_address_array_empty() {
        // ABI encoding of an empty address[]: offset=32, length=0
        let mut data = vec![0u8; 64];
        data[31] = 0x20; // offset = 32
        // length word is all zeros = 0
        let addrs = decode_address_array(&data).unwrap();
        assert!(addrs.is_empty());
    }

    #[test]
    fn decode_address_array_two_addrs() {
        // ABI encoding: offset=32, length=2, addr1, addr2
        let mut data = vec![0u8; 128]; // 4 words
        data[31] = 0x20; // offset = 32
        data[63] = 0x02; // length = 2
        // First address at bytes 64..96 (address in last 20 bytes: 76..96)
        data[76..96].copy_from_slice(&[0xAA; 20]);
        // Second address at bytes 96..128 (address in last 20 bytes: 108..128)
        data[108..128].copy_from_slice(&[0xBB; 20]);

        let addrs = decode_address_array(&data).unwrap();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], [0xAA; 20]);
        assert_eq!(addrs[1], [0xBB; 20]);
    }

    #[test]
    fn decode_address_array_too_short() {
        let data = vec![0u8; 10];
        let addrs = decode_address_array(&data).unwrap();
        assert!(addrs.is_empty());
    }
}
