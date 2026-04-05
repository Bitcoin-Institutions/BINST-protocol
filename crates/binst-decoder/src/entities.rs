//! BINST protocol entity types reconstructed from storage diffs.
//!
//! These types represent the protocol's domain objects as decoded from
//! Bitcoin (via L2 state diffs).  Every type carries a
//! `bitcoin_identity` field linking it across all reachability layers.
//!
//! Authority model — Bitcoin key is sovereign:
//!
//! - **Bitcoin pubkey** — ROOT OF AUTHORITY, controls the inscription UTXO
//! - **Inscription ID** — the entity's permanent identity on Bitcoin
//! - **Membership Rune ID** — check membership in any Rune wallet
//! - **EVM address** — current L2 processing delegate (can change if L2 changes)
//!
//! The L2 contract is a delegate, not the owner. The Bitcoin key holder
//! can redeploy to a different L2 at any time while keeping the same
//! inscription and Rune identity.
//!
//! See `BITCOIN-IDENTITY.md` for the full architecture specification.

use serde::{Deserialize, Serialize};

// ── Bitcoin identity ─────────────────────────────────────────────

/// A Bitcoin-native identity that links a BINST entity across all
/// reachability layers: Bitcoin (inscriptions, Runes) and L2 (EVM contracts).
///
/// The Bitcoin key is the **root of authority**. The entity is defined by
/// the key that controls its inscription UTXO. The L2 EVM address is a
/// processing delegate — it can change if the user switches L2s, but the
/// Bitcoin identity remains the same.
///
/// Authority hierarchy:
/// 1. `bitcoin_pubkey` — root of authority (controls the inscription UTXO)
/// 2. `inscription_id` — the entity's permanent identity on Bitcoin
/// 3. `membership_rune_id` — membership token on Bitcoin
/// 4. `evm_address` — current L2 processing delegate (optional, can change)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BitcoinIdentity {
    /// x-only Taproot public key (32 bytes) — ROOT OF AUTHORITY.
    /// Controls the Ordinal inscription UTXO. Whoever holds the
    /// corresponding private key is the canonical owner of this entity.
    /// All other fields derive from or reference this key.
    pub bitcoin_pubkey: [u8; 32],

    /// Ordinals inscription ID (e.g., "abc123...i0").
    /// Links to the entity's permanent identity inscription on Bitcoin.
    /// Discoverable via any Ordinals explorer using `metaprotocol=binst`.
    pub inscription_id: Option<String>,

    /// Rune ID for the institution's membership token (e.g., "840000:20").
    /// A balance of ≥1 unit = membership in this institution.
    /// Discoverable via any Rune indexer or wallet.
    pub membership_rune_id: Option<String>,

    /// The EVM address (20 bytes) on the current L2 processing delegate.
    /// This is derived from or authorized by the Bitcoin key. It can change
    /// if the user redeploys to a different L2.
    pub evm_address: Option<[u8; 20]>,

    /// Optional derivation path or label for the key.
    /// Useful for HD wallets: e.g. "m/86'/0'/0'/0/0".
    pub derivation_hint: Option<String>,
}

impl BitcoinIdentity {
    /// Create an identity from a Bitcoin public key (the root of authority).
    pub fn from_pubkey(pubkey: [u8; 32]) -> Self {
        Self {
            bitcoin_pubkey: pubkey,
            inscription_id: None,
            membership_rune_id: None,
            evm_address: None,
            derivation_hint: None,
        }
    }

    /// Create an identity from an EVM address when the Bitcoin key is not
    /// yet known. Uses a zeroed pubkey as placeholder — caller must set the
    /// real pubkey when discovered.
    pub fn from_evm(address: [u8; 20]) -> Self {
        Self {
            bitcoin_pubkey: [0u8; 32],
            inscription_id: None,
            membership_rune_id: None,
            evm_address: Some(address),
            derivation_hint: None,
        }
    }

    /// Create an identity with Bitcoin key and L2 EVM address.
    pub fn with_evm(
        pubkey: [u8; 32],
        evm_address: [u8; 20],
        derivation_hint: Option<String>,
    ) -> Self {
        Self {
            bitcoin_pubkey: pubkey,
            inscription_id: None,
            membership_rune_id: None,
            evm_address: Some(evm_address),
            derivation_hint,
        }
    }

    /// Create a full identity with all reachability layers.
    pub fn full(
        pubkey: [u8; 32],
        inscription_id: String,
        membership_rune_id: Option<String>,
        evm_address: Option<[u8; 20]>,
        derivation_hint: Option<String>,
    ) -> Self {
        Self {
            bitcoin_pubkey: pubkey,
            inscription_id: Some(inscription_id),
            membership_rune_id,
            evm_address,
            derivation_hint,
        }
    }

    /// Whether this identity has a real Bitcoin key (not zeroed placeholder).
    pub fn has_bitcoin_key(&self) -> bool {
        self.bitcoin_pubkey != [0u8; 32]
    }

    /// Whether this identity has an Ordinals inscription.
    pub fn has_inscription(&self) -> bool {
        self.inscription_id.is_some()
    }

    /// Whether this identity has a membership Rune.
    pub fn has_membership_rune(&self) -> bool {
        self.membership_rune_id.is_some()
    }

    /// Whether this identity has an L2 delegate address.
    pub fn has_evm_delegate(&self) -> bool {
        self.evm_address.is_some()
    }

    /// Return the Taproot address (bech32m) if a Bitcoin key is set.
    /// Placeholder — actual encoding requires network param and bech32m.
    pub fn taproot_address_hint(&self) -> Option<String> {
        if self.has_bitcoin_key() {
            Some(format!("tb1p{}", hex::encode(&self.bitcoin_pubkey[..20])))
        } else {
            None
        }
    }
}

// ── Protocol entities ────────────────────────────────────────────

/// A BINST Institution reconstructed from storage diffs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstitutionState {
    /// Citrea contract address of this Institution.
    pub contract_address: [u8; 20],

    /// Institution name (from storage slot 0).
    pub name: Option<String>,

    /// Admin identity.
    pub admin: Option<BitcoinIdentity>,

    /// Deployer address (the BINSTDeployer that created this).
    pub deployer: Option<[u8; 20]>,

    /// Known members (from the members array).
    pub members: Vec<BitcoinIdentity>,

    /// Addresses of ProcessTemplate contracts owned by this institution.
    pub process_addresses: Vec<[u8; 20]>,

    /// The Bitcoin block height where we first observed this institution's
    /// state changes.  Useful for anchoring: "this institution was committed
    /// to Bitcoin at height N."
    pub first_seen_btc_height: Option<u64>,

    /// The most recent Bitcoin block height with state changes.
    pub last_seen_btc_height: Option<u64>,
}

impl InstitutionState {
    pub fn new(contract_address: [u8; 20]) -> Self {
        Self {
            contract_address,
            name: None,
            admin: None,
            deployer: None,
            members: Vec::new(),
            process_addresses: Vec::new(),
            first_seen_btc_height: None,
            last_seen_btc_height: None,
        }
    }

    /// Record that this institution was observed at a Bitcoin height.
    pub fn touch(&mut self, btc_height: u64) {
        if self.first_seen_btc_height.is_none() {
            self.first_seen_btc_height = Some(btc_height);
        }
        self.last_seen_btc_height = Some(btc_height);
    }
}

/// A ProcessTemplate reconstructed from storage diffs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTemplateState {
    /// Citrea contract address.
    pub contract_address: [u8; 20],

    /// Template name.
    pub name: Option<String>,

    /// Template description.
    pub description: Option<String>,

    /// Creator identity.
    pub creator: Option<BitcoinIdentity>,

    /// Number of steps in the template.
    pub step_count: Option<u64>,

    /// Step names (if decoded from storage).
    pub step_names: Vec<String>,

    /// How many instances have been created from this template.
    pub instantiation_count: Option<u64>,

    /// Addresses of all ProcessInstance contracts.
    pub instance_addresses: Vec<[u8; 20]>,

    /// Owning institution address (if known from the registry).
    pub institution: Option<[u8; 20]>,

    pub first_seen_btc_height: Option<u64>,
    pub last_seen_btc_height: Option<u64>,
}

impl ProcessTemplateState {
    pub fn new(contract_address: [u8; 20]) -> Self {
        Self {
            contract_address,
            name: None,
            description: None,
            creator: None,
            step_count: None,
            step_names: Vec::new(),
            instantiation_count: None,
            instance_addresses: Vec::new(),
            institution: None,
            first_seen_btc_height: None,
            last_seen_btc_height: None,
        }
    }
}

/// A ProcessInstance reconstructed from storage diffs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInstanceState {
    /// Citrea contract address.
    pub contract_address: [u8; 20],

    /// The ProcessTemplate this instance was created from.
    pub template_address: Option<[u8; 20]>,

    /// Creator identity.
    pub creator: Option<BitcoinIdentity>,

    /// Current step index (0-based).
    pub current_step: Option<u64>,

    /// Total number of steps.
    pub total_steps: Option<u64>,

    /// Whether all steps are completed.
    pub completed: Option<bool>,

    /// Creation timestamp (block.timestamp from Citrea).
    pub created_at: Option<u64>,

    /// Per-step execution records.
    pub step_executions: Vec<StepExecution>,

    pub first_seen_btc_height: Option<u64>,
    pub last_seen_btc_height: Option<u64>,
}

/// A single step execution record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepExecution {
    pub step_index: u64,
    pub status: StepStatus,
    pub actor: Option<BitcoinIdentity>,
    pub timestamp: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepStatus {
    Pending,
    Completed,
    Rejected,
}

impl ProcessInstanceState {
    pub fn new(contract_address: [u8; 20]) -> Self {
        Self {
            contract_address,
            template_address: None,
            creator: None,
            current_step: None,
            total_steps: None,
            completed: None,
            created_at: None,
            step_executions: Vec::new(),
            first_seen_btc_height: None,
            last_seen_btc_height: None,
        }
    }

    /// Computed progress percentage.
    pub fn progress_percent(&self) -> Option<f64> {
        match (self.current_step, self.total_steps) {
            (Some(current), Some(total)) if total > 0 => {
                Some((current as f64 / total as f64) * 100.0)
            }
            _ => None,
        }
    }
}

// ── Aggregate view ───────────────────────────────────────────────

/// The complete protocol state reconstructed from Bitcoin.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProtocolState {
    /// BINSTDeployer contract address.
    pub deployer_address: Option<[u8; 20]>,

    /// All known institutions.
    pub institutions: Vec<InstitutionState>,

    /// All known process templates.
    pub templates: Vec<ProcessTemplateState>,

    /// All known process instances.
    pub instances: Vec<ProcessInstanceState>,

    /// The latest Bitcoin block height we have processed.
    pub tip_btc_height: Option<u64>,

    /// The latest sequencer commitment index we have seen.
    pub tip_commitment_index: Option<u32>,
}
