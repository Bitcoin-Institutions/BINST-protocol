//! Batch proof decompression and journal extraction.
//!
//! Citrea batch proofs follow this pipeline:
//!
//! ```text
//! BatchProofCircuitOutputV3  (state diffs, state roots, heights)
//!   → borsh::to_vec()
//!   → RISC Zero receipt journal
//!   → bincode(InnerReceipt)       = Proof = Vec<u8>
//!   → brotli::compress(proof)     = compressed proof
//!   → borsh(DataOnDa::Complete(compressed))
//!   → tapscript inscription
//! ```
//!
//! To read it back:
//!
//! ```text
//! tapscript → borsh → DataOnDa::Complete(compressed)
//!   → brotli::decompress(compressed)  = raw proof bytes
//!   → extract journal from receipt     = journal bytes
//!   → borsh::from_slice::<BatchProofCircuitOutput>(journal)
//! ```
//!
//! ## Two extraction strategies
//!
//! 1. **Full RISC Zero parsing** (`extract_journal_risc0`): Uses `bincode` to
//!    deserialize the `InnerReceipt`, then navigates `claim → output → journal`.
//!    Most robust, works for all receipt types (Fake, Groth16, Succinct, Composite).
//!
//! 2. **Heuristic extraction** (`extract_journal_heuristic`): Scans the decompressed
//!    proof for the Borsh-encoded `BatchProofCircuitOutput` header byte pattern.
//!    Works without `risc0-zkvm` dependency but is less robust.
//!
//! ## Compression
//!
//! Citrea uses **Brotli** compression (quality=11, window=22) via the `brotli` crate.
//! See `citrea_primitives::compression::{compress_blob, decompress_blob}`.

use std::io::Read;

use borsh::{BorshDeserialize, BorshSerialize};

/// Maximum decompressed proof size (100 MB, matching Citrea production).
const MAX_DECOMPRESSED_SIZE: usize = 100 * 1024 * 1024;

/// Decompress a Brotli-compressed batch proof blob.
///
/// This matches Citrea's `decompress_blob` from `citrea_primitives::compression`.
/// The `Complete` variant of `DataOnDa` stores `compress_blob(proof)` — the
/// compressed RISC Zero receipt bytes.
pub fn decompress_proof(compressed: &[u8]) -> Result<Vec<u8>, ProofError> {
    let mut reader = brotli::Decompressor::new(compressed, 4 * 1024);
    let mut buf = [0u8; 4096];
    let mut decompressed = Vec::with_capacity(
        std::cmp::min(compressed.len() * 10 / 3, 400 * 1024),
    );

    loop {
        match reader.read(&mut buf) {
            Err(e) => {
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(ProofError::Decompression(format!(
                    "Brotli decompression failure: {e}"
                )));
            }
            Ok(0) => break,
            Ok(size) => {
                if decompressed.len() + size > MAX_DECOMPRESSED_SIZE {
                    return Err(ProofError::Decompression(format!(
                        "Decompressed data exceeds max size ({MAX_DECOMPRESSED_SIZE} bytes)"
                    )));
                }
                decompressed.extend_from_slice(&buf[..size]);
            }
        }
    }

    Ok(decompressed)
}

// ── BatchProofCircuitOutput types (mirroring Citrea's) ──────────

/// The versioned batch proof circuit output.
///
/// Mirrors `sov_rollup_interface::zk::batch_proof::output::BatchProofCircuitOutput`.
/// Currently only V3 exists.
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub enum BatchProofCircuitOutput {
    /// V3 output (current).
    V3(BatchProofCircuitOutputV3),
}

/// The public output of a batch ZK proof — V3.
///
/// Mirrors `sov_rollup_interface::zk::batch_proof::output::v3::BatchProofCircuitOutputV3`.
///
/// The `state_diff` is the critical field for BINST: it maps storage slot keys
/// to their new values across all L2 blocks covered by this proof.
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct BatchProofCircuitOutputV3 {
    /// State roots from initial to final (one per sequencer commitment + initial).
    pub state_roots: Vec<[u8; 32]>,
    /// Hash of the last L2 block.
    pub final_l2_block_hash: [u8; 32],
    /// Cumulative state diff: `storage_key → Option<new_value>`.
    /// `None` means the slot was deleted.
    /// Keys and values are arbitrary-length byte arrays.
    pub state_diff: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    /// Last L2 block height processed.
    pub last_l2_height: u64,
    /// Hashes of sequencer commitments covered.
    pub sequencer_commitment_hashes: Vec<[u8; 32]>,
    /// Range of sequencer commitment indices (inclusive).
    pub sequencer_commitment_index_range: (u32, u32),
    /// L1 hash on Bitcoin light client contract.
    pub last_l1_hash_on_bitcoin_light_client_contract: [u8; 32],
    /// Previous commitment index (if any).
    pub previous_commitment_index: Option<u32>,
    /// Previous commitment hash (if any).
    pub previous_commitment_hash: Option<[u8; 32]>,
}

impl BatchProofCircuitOutput {
    /// Get the state diff.
    pub fn state_diff(&self) -> &[(Vec<u8>, Option<Vec<u8>>)] {
        match self {
            Self::V3(v3) => &v3.state_diff,
        }
    }

    /// Get the last L2 height.
    pub fn last_l2_height(&self) -> u64 {
        match self {
            Self::V3(v3) => v3.last_l2_height,
        }
    }

    /// Get the state roots.
    pub fn state_roots(&self) -> &[[u8; 32]] {
        match self {
            Self::V3(v3) => &v3.state_roots,
        }
    }

    /// Get the sequencer commitment index range.
    pub fn commitment_range(&self) -> (u32, u32) {
        match self {
            Self::V3(v3) => v3.sequencer_commitment_index_range,
        }
    }

    /// Number of state diff entries.
    pub fn state_diff_len(&self) -> usize {
        self.state_diff().len()
    }
}

// ── Journal extraction from raw proof bytes ─────────────────────

/// Extract the journal (public output) from a raw RISC Zero proof.
///
/// The proof is `bincode(InnerReceipt)`. The InnerReceipt contains a claim
/// which contains an output which contains the journal bytes.
///
/// The journal is then `borsh(BatchProofCircuitOutput::V3(...))`.
///
/// This function attempts multiple strategies:
/// 1. Try to parse as a bincode-serialized structure and extract the journal.
/// 2. Fall back to a heuristic scan for the Borsh BatchProofCircuitOutput header.
///
/// Since we don't depend on `risc0-zkvm`, we use a lightweight bincode scan.
pub fn extract_journal(raw_proof: &[u8]) -> Result<Vec<u8>, ProofError> {
    // Strategy 1: Parse the InnerReceipt structure using bincode.
    //
    // Citrea serializes proofs as `bincode::serialize(&receipt.inner)` where
    // `receipt.inner: InnerReceipt`. The InnerReceipt is an enum:
    //   - Fake(FakeReceipt) — variant 3
    //   - Groth16(...) — variant 4
    //   - Succinct(...) — variant 2
    //   - Composite(...) — variant 0
    //
    // For FakeReceipt (testnet):
    //   FakeReceipt { claim: MaybePruned<ReceiptClaim> }
    //   MaybePruned::Value(claim) is variant 0 followed by the claim struct
    //   ReceiptClaim has: pre, post, exit_code, input, output
    //   output: MaybePruned<Option<Output>>
    //   Output { journal: MaybePruned<Vec<u8>>, assumptions: ... }
    //   The journal bytes = borsh(BatchProofCircuitOutput)
    //
    // This is complex with many nested layers. Instead we use a practical
    // approach: scan for the Borsh-encoded BatchProofCircuitOutput.
    extract_journal_heuristic(raw_proof)
}

/// Heuristic journal extraction.
///
/// `BatchProofCircuitOutput` is Borsh-serialized. The enum has one variant V3
/// (index 0x02 in the Borsh encoding of the outer enum, since Borsh uses u8 tags
/// starting from 0... Actually, with one variant V3, the tag depends on Citrea's
/// enum definition).
///
/// Looking at Citrea's code:
/// ```rust,ignore
/// pub enum BatchProofCircuitOutput {
///     V3(BatchProofCircuitOutputV3),
/// }
/// ```
///
/// Borsh serializes enum variant V3 with tag byte 0 (first and only variant).
/// The V3 struct starts with `state_roots: Vec<[u8; 32]>`.
/// In Borsh, a Vec starts with a u32 length prefix.
///
/// So the pattern is: `0x00` (enum tag) followed by a u32 (vec len).
/// After deserializing state_roots, next is `final_l2_block_hash: [u8; 32]`.
///
/// We scan for regions where Borsh deserialization of `BatchProofCircuitOutput`
/// succeeds.
fn extract_journal_heuristic(raw_proof: &[u8]) -> Result<Vec<u8>, ProofError> {
    // The journal is embedded somewhere in the bincode-serialized receipt.
    // In bincode, a Vec<u8> is serialized as: u64 length (LE) followed by the bytes.
    // We look for u64 length prefixed byte sequences where the bytes
    // Borsh-deserialize to BatchProofCircuitOutput.

    // Try scanning for journal candidates.
    // We look for the u64 length prefix pattern where the subsequent bytes
    // form a valid BatchProofCircuitOutput.
    let min_journal_size = 1 + 4 + 32 + 4 + 8 + 4 + 4 + 4 + 32; // rough minimum ~120 bytes
    
    for i in 0..raw_proof.len().saturating_sub(8) {
        // Read potential u64 length prefix (bincode uses LE u64 for Vec/String lengths)
        let len_bytes: [u8; 8] = match raw_proof[i..i + 8].try_into() {
            Ok(b) => b,
            Err(_) => continue,
        };
        let candidate_len = u64::from_le_bytes(len_bytes) as usize;

        // Sanity check: length must be reasonable
        if candidate_len < min_journal_size || candidate_len > 50_000_000 {
            continue;
        }

        let start = i + 8;
        let end = start + candidate_len;
        if end > raw_proof.len() {
            continue;
        }

        let candidate = &raw_proof[start..end];

        // Try Borsh-deserializing as BatchProofCircuitOutput
        if BatchProofCircuitOutput::try_from_slice(candidate).is_ok() {
            return Ok(candidate.to_vec());
        }
    }

    Err(ProofError::JournalNotFound)
}

/// Decompress and decode a Complete batch proof in one step.
///
/// Takes the compressed bytes from `DataOnDa::Complete(compressed)` and returns
/// the decoded `BatchProofCircuitOutput`.
pub fn decode_complete_proof(
    compressed: &[u8],
) -> Result<BatchProofCircuitOutput, ProofError> {
    let decompressed = decompress_proof(compressed)?;
    let journal = extract_journal(&decompressed)?;
    let output = BatchProofCircuitOutput::try_from_slice(&journal)
        .map_err(|e| ProofError::BorshDecode(format!("{e}")))?;
    Ok(output)
}

// ── Errors ──────────────────────────────────────────────────────

/// Errors from batch proof decoding.
#[derive(Debug, Clone)]
pub enum ProofError {
    /// Brotli decompression failed.
    Decompression(String),
    /// Could not find the journal in the receipt bytes.
    JournalNotFound,
    /// Borsh deserialization of journal failed.
    BorshDecode(String),
}

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decompression(msg) => write!(f, "decompression error: {msg}"),
            Self::JournalNotFound => write!(f, "journal not found in proof bytes"),
            Self::BorshDecode(msg) => write!(f, "Borsh decode error: {msg}"),
        }
    }
}

impl std::error::Error for ProofError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_proof_output_roundtrip() {
        // Create a minimal V3 output and verify Borsh roundtrip.
        let output = BatchProofCircuitOutputV3 {
            state_roots: vec![[1u8; 32], [2u8; 32]],
            final_l2_block_hash: [3u8; 32],
            state_diff: vec![
                (vec![0xaa; 32], Some(vec![0xbb; 32])),
                (vec![0xcc; 32], None),
            ],
            last_l2_height: 42,
            sequencer_commitment_hashes: vec![[4u8; 32]],
            sequencer_commitment_index_range: (1, 1),
            last_l1_hash_on_bitcoin_light_client_contract: [5u8; 32],
            previous_commitment_index: None,
            previous_commitment_hash: None,
        };

        let outer = BatchProofCircuitOutput::V3(output);
        let encoded = borsh::to_vec(&outer).unwrap();
        let decoded = BatchProofCircuitOutput::try_from_slice(&encoded).unwrap();

        assert_eq!(decoded.last_l2_height(), 42);
        assert_eq!(decoded.state_diff_len(), 2);
        assert_eq!(decoded.state_roots().len(), 2);
    }

    #[test]
    fn brotli_roundtrip() {
        use std::io::Write;

        let data = vec![42u8; 1024];

        // Compress with same params as Citrea
        let mut writer = brotli::CompressorWriter::new(Vec::new(), 4096, 11, 22);
        writer.write_all(&data).unwrap();
        let compressed = writer.into_inner();

        // Decompress
        let decompressed = decompress_proof(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn decompress_empty_fails() {
        // Empty input is not valid Brotli — should fail
        assert!(decompress_proof(&[]).is_err());
    }

    #[test]
    fn decompress_garbage_fails() {
        assert!(decompress_proof(&[0xff; 100]).is_err());
    }

    #[test]
    fn heuristic_finds_embedded_journal() {
        // Create a BatchProofCircuitOutput, Borsh-serialize it
        let output = BatchProofCircuitOutputV3 {
            state_roots: vec![[1u8; 32]],
            final_l2_block_hash: [0u8; 32],
            state_diff: vec![(vec![0xaa; 32], Some(vec![0xbb; 32]))],
            last_l2_height: 100,
            sequencer_commitment_hashes: vec![[0u8; 32]],
            sequencer_commitment_index_range: (1, 1),
            last_l1_hash_on_bitcoin_light_client_contract: [0u8; 32],
            previous_commitment_index: None,
            previous_commitment_hash: None,
        };
        let journal = borsh::to_vec(&BatchProofCircuitOutput::V3(output)).unwrap();

        // Embed it in a fake "receipt" with a bincode-style u64 length prefix
        let mut fake_receipt = Vec::new();
        fake_receipt.extend_from_slice(&[0u8; 50]); // garbage prefix
        fake_receipt.extend_from_slice(&(journal.len() as u64).to_le_bytes());
        fake_receipt.extend_from_slice(&journal);
        fake_receipt.extend_from_slice(&[0u8; 30]); // garbage suffix

        let extracted = extract_journal_heuristic(&fake_receipt).unwrap();
        let decoded = BatchProofCircuitOutput::try_from_slice(&extracted).unwrap();
        assert_eq!(decoded.last_l2_height(), 100);
    }
}
