//! Shared types for EVM interaction.

use serde::{Deserialize, Serialize};

/// Citrea finality status — last committed and proven L2 heights.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2FinalityStatus {
    pub committed_height: u64,
    pub committed_batch_index: u64,
    pub proven_height: u64,
    pub proven_batch_index: u64,
}

/// Finality tier classification for an L2 block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalityTier {
    /// Block exists on L2 but not yet committed to Bitcoin.
    SoftConfirmation,
    /// Sequencer commitment inscribed on Bitcoin.
    Committed,
    /// ZK batch proof verified on Bitcoin — strongest tier.
    Proven,
}

impl FinalityTier {
    /// Classify a block height against the current finality boundaries.
    pub fn classify(block_height: u64, status: &L2FinalityStatus) -> Self {
        if block_height <= status.proven_height {
            FinalityTier::Proven
        } else if block_height <= status.committed_height {
            FinalityTier::Committed
        } else {
            FinalityTier::SoftConfirmation
        }
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            FinalityTier::SoftConfirmation => "Soft Confirmation",
            FinalityTier::Committed => "Committed",
            FinalityTier::Proven => "Proven",
        }
    }

    /// Badge color hint (for UI consumers).
    pub fn color(&self) -> &'static str {
        match self {
            FinalityTier::SoftConfirmation => "yellow",
            FinalityTier::Committed => "blue",
            FinalityTier::Proven => "green",
        }
    }
}

/// Transaction receipt (subset of fields we care about).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxReceipt {
    pub status: bool,
    pub block_number: u64,
    pub gas_used: u64,
    pub contract_address: Option<String>,
    pub logs: Vec<LogEntry>,
}

/// A single event log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
}

/// Step status enum matching the Solidity `StepStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StepStatus {
    Pending = 0,
    Completed = 1,
    Rejected = 2,
}

impl StepStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Pending),
            1 => Some(Self::Completed),
            2 => Some(Self::Rejected),
            _ => None,
        }
    }
}
