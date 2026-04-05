//! Citrea JMT (Jellyfish Merkle Tree) key parsing and construction.
//!
//! Citrea state diffs use **StorageKey** preimages as keys, not raw EVM
//! address:slot pairs.  Each key begins with a module prefix that identifies
//! the state category:
//!
//! | prefix  | hex          | meaning                | key suffix          |
//! |---------|--------------|------------------------|---------------------|
//! | `E/s/`  | `452f732f`   | EVM storage            | 32-byte storage hash|
//! | `E/a/`  | `452f612f`   | EVM account (by id)    | 8-byte account_id LE|
//! | `E/i/`  | `452f692f`   | EVM account index      | 20-byte address     |
//! | `E/H/`  | `452f482f`   | EVM block header       | 8-byte block# LE   |
//! | `E/n/`  | `452f6e2f`   | EVM account count      | (singleton)         |
//! | `E/h/`  | `452f682f`   | EVM head block number  | (singleton)         |
//! | `A/a/`  | `412f612f`   | accounts_manager       | 33-byte key         |
//! | `L/da`  | `4c2f6461`   | ledger DA              | 3-byte suffix       |
//!
//! ## Storage hash
//!
//! The 32-byte suffix in `E/s/` keys is computed as:
//!
//! ```text
//! storage_hash = SHA-256(contract_address_20_bytes || slot_as_U256_le_bytes)
//! ```
//!
//! This is a **one-way hash**.  We cannot reverse it to recover `(address, slot)`.
//! Instead, we **forward-compute** the expected keys for every BINST contract +
//! slot combination of interest, then match incoming state diff entries against
//! our pre-computed lookup table.

use sha2::{Digest, Sha256};

/// The 4-byte prefix for EVM storage entries in Citrea's JMT.
pub const EVM_STORAGE_PREFIX: &[u8; 4] = b"E/s/";
/// The 4-byte prefix for EVM account index (address → id).
pub const EVM_ACCOUNT_IDX_PREFIX: &[u8; 4] = b"E/i/";
/// The 4-byte prefix for EVM account data (id → info).
pub const EVM_ACCOUNT_PREFIX: &[u8; 4] = b"E/a/";
/// The 4-byte prefix for EVM block headers.
pub const EVM_HEADER_PREFIX: &[u8; 4] = b"E/H/";

/// Categorised JMT state diff entry.
#[derive(Debug, Clone)]
pub enum JmtEntry<'a> {
    /// EVM storage: `E/s/` + 32-byte storage hash → value
    EvmStorage {
        storage_hash: [u8; 32],
        value: Option<&'a [u8]>,
    },
    /// EVM account index: `E/i/` + 20-byte address → 8-byte account_id LE
    EvmAccountIndex {
        address: [u8; 20],
        value: Option<&'a [u8]>,
    },
    /// EVM account data: `E/a/` + 8-byte id → account info (borsh)
    EvmAccount {
        account_id: u64,
        value: Option<&'a [u8]>,
    },
    /// EVM block header: `E/H/` + 8-byte block number LE → header data
    EvmHeader {
        block_number: u64,
        value: Option<&'a [u8]>,
    },
    /// Any other key we don't specifically parse.
    Other {
        key: &'a [u8],
        value: Option<&'a [u8]>,
    },
}

/// Parse a raw JMT state diff entry into a categorised [`JmtEntry`].
pub fn parse_jmt_entry<'a>(key: &'a [u8], value: Option<&'a [u8]>) -> JmtEntry<'a> {
    if key.len() >= 4 {
        let prefix: &[u8; 4] = key[..4].try_into().unwrap();

        match prefix {
            b"E/s/" if key.len() == 36 => {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&key[4..36]);
                JmtEntry::EvmStorage {
                    storage_hash: hash,
                    value,
                }
            }
            b"E/i/" if key.len() == 24 => {
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&key[4..24]);
                JmtEntry::EvmAccountIndex {
                    address: addr,
                    value,
                }
            }
            b"E/a/" if key.len() == 12 => {
                let id = u64::from_le_bytes(key[4..12].try_into().unwrap());
                JmtEntry::EvmAccount {
                    account_id: id,
                    value,
                }
            }
            b"E/H/" if key.len() == 12 => {
                let num = u64::from_le_bytes(key[4..12].try_into().unwrap());
                JmtEntry::EvmHeader {
                    block_number: num,
                    value,
                }
            }
            _ => JmtEntry::Other { key, value },
        }
    } else {
        JmtEntry::Other { key, value }
    }
}

/// Compute the Citrea EVM storage hash for a given `(contract_address, slot)`.
///
/// This mirrors `Evm::get_storage_address()` in Citrea:
/// ```ignore
/// SHA-256(address_20_bytes || slot_as_U256_le_32_bytes)
/// ```
/// The result is 32 bytes, stored in the JMT key as `E/s/ || result`.
///
/// `slot_be` is the 32-byte EVM storage slot in **big-endian** (the standard
/// Solidity representation).  We convert to little-endian U256 internally,
/// matching Citrea's `U256::as_le_slice()`.
pub fn evm_storage_hash(address: &[u8; 20], slot_be: &[u8; 32]) -> [u8; 32] {
    // Convert slot from big-endian to little-endian (Citrea uses alloy U256 LE)
    let mut slot_le = *slot_be;
    slot_le.reverse();

    let mut hasher = Sha256::new();
    hasher.update(address);
    hasher.update(&slot_le);
    let result = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Build the full 36-byte JMT key for an EVM storage entry.
pub fn evm_storage_jmt_key(address: &[u8; 20], slot_be: &[u8; 32]) -> [u8; 36] {
    let hash = evm_storage_hash(address, slot_be);
    let mut key = [0u8; 36];
    key[..4].copy_from_slice(EVM_STORAGE_PREFIX);
    key[4..36].copy_from_slice(&hash);
    key
}

/// Convenience: compute the storage hash for a simple `u64` slot number.
pub fn evm_storage_hash_simple(address: &[u8; 20], slot: u64) -> [u8; 32] {
    let mut slot_be = [0u8; 32];
    slot_be[24..32].copy_from_slice(&slot.to_be_bytes());
    evm_storage_hash(address, &slot_be)
}

/// Summary of prefix categories found in a state diff.
#[derive(Debug, Default)]
pub struct JmtDiffSummary {
    pub evm_storage: usize,
    pub evm_account_idx: usize,
    pub evm_account: usize,
    pub evm_header: usize,
    pub other: usize,
}

/// Produce a quick summary of a state diff's key categories.
pub fn summarize_diff(entries: &[(Vec<u8>, Option<Vec<u8>>)]) -> JmtDiffSummary {
    let mut summary = JmtDiffSummary::default();
    for (key, value) in entries {
        match parse_jmt_entry(key, value.as_deref()) {
            JmtEntry::EvmStorage { .. } => summary.evm_storage += 1,
            JmtEntry::EvmAccountIndex { .. } => summary.evm_account_idx += 1,
            JmtEntry::EvmAccount { .. } => summary.evm_account += 1,
            JmtEntry::EvmHeader { .. } => summary.evm_header += 1,
            JmtEntry::Other { .. } => summary.other += 1,
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_evm_storage_entry() {
        let mut key = vec![b'E', b'/', b's', b'/'];
        key.extend_from_slice(&[0xAB; 32]);
        let entry = parse_jmt_entry(&key, Some(&[0x01]));
        match entry {
            JmtEntry::EvmStorage { storage_hash, .. } => {
                assert_eq!(storage_hash, [0xAB; 32]);
            }
            _ => panic!("Expected EvmStorage"),
        }
    }

    #[test]
    fn parse_evm_account_index() {
        let mut key = vec![b'E', b'/', b'i', b'/'];
        key.extend_from_slice(&[0x42; 20]);
        let entry = parse_jmt_entry(&key, Some(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
        match entry {
            JmtEntry::EvmAccountIndex { address, .. } => {
                assert_eq!(address, [0x42; 20]);
            }
            _ => panic!("Expected EvmAccountIndex"),
        }
    }

    #[test]
    fn parse_evm_account() {
        let mut key = vec![b'E', b'/', b'a', b'/'];
        key.extend_from_slice(&42u64.to_le_bytes());
        let entry = parse_jmt_entry(&key, None);
        match entry {
            JmtEntry::EvmAccount { account_id, .. } => {
                assert_eq!(account_id, 42);
            }
            _ => panic!("Expected EvmAccount"),
        }
    }

    #[test]
    fn parse_evm_header() {
        let mut key = vec![b'E', b'/', b'H', b'/'];
        key.extend_from_slice(&100u64.to_le_bytes());
        let entry = parse_jmt_entry(&key, Some(&[0xFF; 32]));
        match entry {
            JmtEntry::EvmHeader { block_number, .. } => {
                assert_eq!(block_number, 100);
            }
            _ => panic!("Expected EvmHeader"),
        }
    }

    #[test]
    fn evm_storage_hash_deterministic() {
        let addr = [0x42u8; 20];
        let slot = [0u8; 32]; // slot 0
        let h1 = evm_storage_hash(&addr, &slot);
        let h2 = evm_storage_hash(&addr, &slot);
        assert_eq!(h1, h2);
        // Different address → different hash
        let addr2 = [0x43u8; 20];
        let h3 = evm_storage_hash(&addr2, &slot);
        assert_ne!(h1, h3);
    }

    #[test]
    fn evm_storage_hash_simple_matches_full() {
        let addr = [0x42u8; 20];
        let h1 = evm_storage_hash_simple(&addr, 7);
        let mut slot_be = [0u8; 32];
        slot_be[24..32].copy_from_slice(&7u64.to_be_bytes());
        let h2 = evm_storage_hash(&addr, &slot_be);
        assert_eq!(h1, h2);
    }

    #[test]
    fn jmt_key_has_correct_prefix() {
        let addr = [0x01u8; 20];
        let slot = [0u8; 32];
        let key = evm_storage_jmt_key(&addr, &slot);
        assert_eq!(&key[..4], b"E/s/");
        assert_eq!(key.len(), 36);
    }

    #[test]
    fn summarize_mixed_diff() {
        let entries = vec![
            // E/s/ entry
            ({
                let mut k = b"E/s/".to_vec();
                k.extend_from_slice(&[0u8; 32]);
                k
            }, Some(vec![1u8])),
            // E/H/ entry
            ({
                let mut k = b"E/H/".to_vec();
                k.extend_from_slice(&[0u8; 8]);
                k
            }, Some(vec![2u8])),
            // E/i/ entry
            ({
                let mut k = b"E/i/".to_vec();
                k.extend_from_slice(&[0u8; 20]);
                k
            }, None),
            // Unknown
            (b"L/da/xx".to_vec(), Some(vec![3u8])),
        ];

        let summary = summarize_diff(&entries);
        assert_eq!(summary.evm_storage, 1);
        assert_eq!(summary.evm_header, 1);
        assert_eq!(summary.evm_account_idx, 1);
        assert_eq!(summary.other, 1);
    }
}
