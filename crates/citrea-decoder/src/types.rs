//! Citrea DA types — mirrors the on-chain Borsh-serialized structures.

use borsh::{BorshDeserialize, BorshSerialize};

/// Transaction kind encoded in the tapscript header (2 bytes LE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TransactionKind {
    /// Complete batch proof (fits in one tx, < 397 KB).
    Complete = 0,
    /// Aggregate — references chunk txids for a large proof.
    Aggregate = 1,
    /// Chunk — part of an aggregate proof.
    Chunk = 2,
    /// Batch proof method ID update (security council signatures).
    BatchProofMethodId = 3,
    /// Sequencer commitment — posted after each soft-confirmation batch.
    SequencerCommitment = 4,
}

impl TransactionKind {
    pub fn from_le_bytes(bytes: [u8; 2]) -> Option<Self> {
        match u16::from_le_bytes(bytes) {
            0 => Some(Self::Complete),
            1 => Some(Self::Aggregate),
            2 => Some(Self::Chunk),
            3 => Some(Self::BatchProofMethodId),
            4 => Some(Self::SequencerCommitment),
            _ => None,
        }
    }
}

impl core::fmt::Display for TransactionKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Complete => write!(f, "Complete"),
            Self::Aggregate => write!(f, "Aggregate"),
            Self::Chunk => write!(f, "Chunk"),
            Self::BatchProofMethodId => write!(f, "BatchProofMethodId"),
            Self::SequencerCommitment => write!(f, "SequencerCommitment"),
        }
    }
}

// ── Borsh-serialized envelope ────────────────────────────────────

/// The top-level enum written to DA. Borsh uses a 1-byte variant index.
///
/// Must match Citrea's `DataOnDa` enum ordering exactly.
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub enum DataOnDa {
    /// Variant 0 — complete ZK proof (compressed).
    Complete(Vec<u8>),
    /// Variant 1 — aggregate: lists of txids and wtxids referencing chunks.
    Aggregate(Vec<[u8; 32]>, Vec<[u8; 32]>),
    /// Variant 2 — a single chunk of a large proof.
    Chunk(Vec<u8>),
    /// Variant 3 — batch proof method ID (security council).
    BatchProofMethodId(BatchProofMethodIdData),
    /// Variant 4 — sequencer commitment.
    SequencerCommitment(SequencerCommitment),
}

/// A sequencer commitment — the most common inscription type.
///
/// Posted by the sequencer after batching soft confirmations.
/// The `merkle_root` covers the L2 block hashes in this batch.
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct SequencerCommitment {
    /// Merkle root of the L2 block hashes in this commitment.
    pub merkle_root: [u8; 32],
    /// Absolute sequential index (0, 1, 2, ...).
    pub index: u32,
    /// The last L2 block number covered by this commitment.
    pub l2_end_block_number: u64,
}

/// Batch proof method ID — carries security council signatures.
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct BatchProofMethodIdData {
    pub method_id: Vec<u8>,
    pub signatures: Vec<Vec<u8>>,
    pub public_keys: Vec<Vec<u8>>,
}

// ── Parsed inscription (pre-Borsh) ──────────────────────────────

/// A fully parsed Citrea inscription extracted from a Bitcoin tapscript.
#[derive(Debug, Clone)]
pub struct ParsedInscription {
    /// The x-only public key from the tapscript header (DA key).
    pub tapscript_pubkey: [u8; 32],
    /// Transaction kind from the 2-byte header.
    pub kind: TransactionKind,
    /// Schnorr signature over the body (authentication).
    pub signature: Vec<u8>,
    /// Signer's public key (compressed, 33 bytes).
    pub signer_pubkey: Vec<u8>,
    /// Raw body bytes (Borsh-encoded `DataOnDa`).
    pub body: Vec<u8>,
    /// Nonce used to mine the wtxid prefix.
    pub nonce: i64,
}

impl ParsedInscription {
    /// Borsh-deserialize the body into a `DataOnDa` enum.
    pub fn decode_body(&self) -> Result<DataOnDa, borsh::io::Error> {
        DataOnDa::try_from_slice(&self.body)
    }

    /// If this is a SequencerCommitment, extract it directly.
    pub fn as_sequencer_commitment(&self) -> Option<SequencerCommitment> {
        if self.kind != TransactionKind::SequencerCommitment {
            return None;
        }
        match self.decode_body() {
            Ok(DataOnDa::SequencerCommitment(sc)) => Some(sc),
            _ => None,
        }
    }
}

/// The production wtxid prefix used to identify Citrea reveal transactions.
pub const REVEAL_TX_PREFIX: &[u8] = &[0x02, 0x02];

/// Testing wtxid prefix (1 byte).
pub const REVEAL_TX_PREFIX_TEST: &[u8] = &[0x02];
