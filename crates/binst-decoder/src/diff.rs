//! Map raw state diffs from batch proofs to BINST protocol entity changes.
//!
//! Given a set of known BINST contract addresses and a raw state diff
//! `(key, Option<value>)` from a `BatchProofCircuitOutputV3`, this module
//! identifies which storage slots changed and what they mean in BINST terms.
//!
//! ## Architecture
//!
//! ```text
//! BatchProofCircuitOutputV3.state_diff
//!   → parse JMT keys (E/s/, E/a/, E/i/, E/H/, …)
//!   → match E/s/ storage hashes against pre-computed BINST lookup table
//!   → decode matched slots into BinstStateChange
//! ```
//!
//! ## Storage key format (Citrea JMT)
//!
//! Citrea's state diff keys are **JMT StorageKey preimages**, not raw EVM
//! address:slot pairs.  EVM storage entries use the prefix `E/s/` followed
//! by a 32-byte **storage hash**:
//!
//! ```text
//! storage_hash = SHA-256(contract_address ‖ slot_as_U256_le)
//! ```
//!
//! This is a one-way hash, so we pre-compute the expected hashes for every
//! BINST contract + slot of interest and match incoming entries against our
//! lookup table.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::jmt::{self, JmtEntry};
use crate::storage;
use crate::value;

/// A meaningful state change in a BINST contract, decoded from a raw storage diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinstStateChange {
    /// Which contract was affected.
    pub contract: ContractKind,
    /// The contract's EVM address (20 bytes), if known.
    pub contract_address: Option<[u8; 20]>,
    /// What field changed.
    pub field: FieldChange,
    /// Raw storage slot key (hex).
    pub raw_key: String,
    /// Raw new value (hex), or None if deleted.
    pub raw_value: Option<String>,
    /// Human-readable decoded value.
    pub decoded: value::DecodedValue,
}

/// The kind of BINST contract that was affected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractKind {
    Institution,
    ProcessTemplate,
    ProcessInstance,
    BINSTDeployer,
    /// A contract address that we don't recognize.
    Unknown,
}

/// A decoded field-level change in a BINST contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldChange {
    // ── Institution ──
    InstitutionName,
    InstitutionAdmin,
    InstitutionDeployer,
    InstitutionInscriptionId,
    InstitutionRuneId,
    InstitutionBtcPubkey,
    InstitutionMembersLength,
    InstitutionMemberElement { index: u64 },
    InstitutionIsMember { key_hint: String },
    InstitutionProcessesLength,
    InstitutionProcessElement { index: u64 },

    // ── ProcessTemplate ──
    TemplateName,
    TemplateDescription,
    TemplateCreator,
    TemplateStepsLength,
    TemplateInstantiationCount,
    TemplateAllInstancesLength,
    TemplateInstanceElement { index: u64 },

    // ── ProcessInstance ──
    InstanceTemplate,
    InstanceCreator,
    InstanceCurrentStepIndex,
    InstanceTotalSteps,
    InstanceCompleted,
    InstanceCreatedAt,
    InstanceStepState { step_index: u64 },

    // ── BINSTDeployer ──
    DeployerInstitutionsLength,
    DeployerInstitutionElement { index: u64 },
    DeployerProcessesLength,
    DeployerProcessElement { index: u64 },

    /// A storage slot we don't recognize.
    UnknownSlot { slot_hex: String },
}

/// A registry of known BINST contract addresses with a pre-computed lookup
/// table of JMT storage hashes.
///
/// Call [`BinstRegistry::build_lookup`] after adding all addresses to
/// populate the hash map used by [`map_state_diff`].
#[derive(Debug, Clone, Default)]
pub struct BinstRegistry {
    /// Known deployer addresses.
    pub deployers: Vec<[u8; 20]>,
    /// Known institution addresses.
    pub institutions: Vec<[u8; 20]>,
    /// Known template addresses.
    pub templates: Vec<[u8; 20]>,
    /// Known instance addresses.
    pub instances: Vec<[u8; 20]>,

    /// Pre-computed storage_hash → slot entry lookup table.
    /// Populated by [`build_lookup`].
    lookup: HashMap<[u8; 32], SlotEntry>,
}

/// A pre-computed entry: storage_hash → (contract address, contract kind, EVM slot)
#[derive(Debug, Clone)]
struct SlotEntry {
    address: [u8; 20],
    kind: ContractKind,
    /// The original EVM storage slot in big-endian (32 bytes).
    slot_be: [u8; 32],
}

impl BinstRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a deployer address.
    pub fn add_deployer(&mut self, addr: [u8; 20]) {
        if !self.deployers.contains(&addr) {
            self.deployers.push(addr);
        }
    }

    /// Register an institution address.
    pub fn add_institution(&mut self, addr: [u8; 20]) {
        if !self.institutions.contains(&addr) {
            self.institutions.push(addr);
        }
    }

    /// Register a process template address.
    pub fn add_template(&mut self, addr: [u8; 20]) {
        if !self.templates.contains(&addr) {
            self.templates.push(addr);
        }
    }

    /// Register a process instance address.
    pub fn add_instance(&mut self, addr: [u8; 20]) {
        if !self.instances.contains(&addr) {
            self.instances.push(addr);
        }
    }

    /// Look up which contract kind an address belongs to.
    pub fn kind_of(&self, addr: &[u8; 20]) -> ContractKind {
        if self.deployers.contains(addr) {
            ContractKind::BINSTDeployer
        } else if self.institutions.contains(addr) {
            ContractKind::Institution
        } else if self.templates.contains(addr) {
            ContractKind::ProcessTemplate
        } else if self.instances.contains(addr) {
            ContractKind::ProcessInstance
        } else {
            ContractKind::Unknown
        }
    }

    /// Backward-compat alias.
    pub fn lookup(&self, addr: &[u8; 20]) -> ContractKind {
        self.kind_of(addr)
    }

    /// Total number of registered addresses.
    pub fn len(&self) -> usize {
        self.deployers.len()
            + self.institutions.len()
            + self.templates.len()
            + self.instances.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if an address is known.
    pub fn contains(&self, addr: &[u8; 20]) -> bool {
        self.kind_of(addr) != ContractKind::Unknown
    }

    /// Number of entries in the pre-computed lookup table.
    pub fn lookup_table_size(&self) -> usize {
        self.lookup.len()
    }

    /// Build (or rebuild) the pre-computed JMT storage hash lookup table.
    ///
    /// For each registered contract address, we compute the SHA-256 storage
    /// hash for every "interesting" EVM storage slot (simple slots, array
    /// base+elements, mapping entries up to a reasonable bound).
    ///
    /// This must be called after all addresses have been registered and
    /// before calling [`map_state_diff`].
    pub fn build_lookup(&mut self) {
        self.lookup.clear();

        let mut insert =
            |addr: &[u8; 20], kind: ContractKind, slots: &[[u8; 32]]| {
                for slot_be in slots {
                    let hash = jmt::evm_storage_hash(addr, slot_be);
                    self.lookup.insert(
                        hash,
                        SlotEntry {
                            address: *addr,
                            kind,
                            slot_be: *slot_be,
                        },
                    );
                }
            };

        for addr in self.deployers.clone() {
            insert(&addr, ContractKind::BINSTDeployer, &deployer_slots());
        }
        for addr in self.institutions.clone() {
            insert(&addr, ContractKind::Institution, &institution_slots());
        }
        for addr in self.templates.clone() {
            insert(&addr, ContractKind::ProcessTemplate, &template_slots());
        }
        for addr in self.instances.clone() {
            insert(&addr, ContractKind::ProcessInstance, &instance_slots());
        }
    }

    /// Look up a JMT storage hash in the pre-computed table.
    fn resolve_storage_hash(&self, hash: &[u8; 32]) -> Option<&SlotEntry> {
        self.lookup.get(hash)
    }
}

/// Produce all "interesting" EVM storage slots for Institution.sol.
fn institution_slots() -> Vec<[u8; 32]> {
    let mut slots = Vec::new();
    for s in 0..=8u64 {
        slots.push(slot_be(s));
    }
    for i in 0..256u64 {
        slots.push(storage::array_element(storage::institution::MEMBERS_ARRAY, i));
        slots.push(storage::array_element(storage::institution::PROCESSES_ARRAY, i));
    }
    slots
}

/// Produce all "interesting" EVM storage slots for ProcessTemplate.sol.
fn template_slots() -> Vec<[u8; 32]> {
    let mut slots = Vec::new();
    for s in 0..=6u64 {
        slots.push(slot_be(s));
    }
    for i in 0..256u64 {
        slots.push(storage::array_element(storage::template::ALL_INSTANCES_ARRAY, i));
    }
    slots
}

/// Produce all "interesting" EVM storage slots for ProcessInstance.sol.
fn instance_slots() -> Vec<[u8; 32]> {
    let mut slots = Vec::new();
    for s in 0..=6u64 {
        slots.push(slot_be(s));
    }
    for step in 0..64u64 {
        slots.push(storage::mapping_slot_uint(step, storage::instance::STEP_STATES_MAP));
    }
    slots
}

/// Produce all "interesting" EVM storage slots for BINSTDeployer.sol.
fn deployer_slots() -> Vec<[u8; 32]> {
    let mut slots = Vec::new();
    for s in 0..=1u64 {
        slots.push(slot_be(s));
    }
    for i in 0..256u64 {
        slots.push(storage::array_element(storage::deployer::INSTITUTIONS_ARRAY, i));
        slots.push(storage::array_element(storage::deployer::DEPLOYED_PROCESSES_ARRAY, i));
    }
    slots
}

/// Convert a small slot number to a 32-byte big-endian word.
fn slot_be(slot: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[24..32].copy_from_slice(&slot.to_be_bytes());
    buf
}

// ── Main entry point: map a whole state diff ──────────────────────

/// Map a raw JMT state diff (from a batch proof) to BINST state changes.
///
/// The `entries` are `(key, Option<value>)` pairs straight from
/// `BatchProofCircuitOutputV3.state_diff`.
///
/// The registry must have been populated and [`BinstRegistry::build_lookup`]
/// called before invoking this function.
///
/// Returns only the entries that matched a known BINST contract slot.
pub fn map_state_diff(
    registry: &BinstRegistry,
    entries: &[(Vec<u8>, Option<Vec<u8>>)],
) -> Vec<BinstStateChange> {
    let mut changes = Vec::new();

    for (key, value) in entries {
        let entry = jmt::parse_jmt_entry(key, value.as_deref());

        match entry {
            JmtEntry::EvmStorage {
                storage_hash,
                value,
            } => {
                if let Some(slot_entry) = registry.resolve_storage_hash(&storage_hash) {
                    let field = decode_slot(slot_entry.kind, &slot_entry.slot_be);
                    let raw_value = value.map(hex::encode);
                    let decoded =
                        value::decode_value(&field, raw_value.as_deref());
                    changes.push(BinstStateChange {
                        contract: slot_entry.kind,
                        contract_address: Some(slot_entry.address),
                        field,
                        raw_key: hex::encode(key),
                        raw_value,
                        decoded,
                    });
                }
            }
            _ => {
                // E/a/, E/i/, E/H/, L/da etc. — not BINST storage changes
            }
        }
    }

    changes
}

/// Decode a raw state diff entry's storage slot into a BINST field change.
///
/// `slot` is the 32-byte storage slot key. We match it against known slot
/// patterns for the given contract kind.
pub fn decode_slot(kind: ContractKind, slot: &[u8; 32]) -> FieldChange {
    // Convert slot to u64 if it's a simple small slot number
    let slot_u64 = slot_to_u64(slot);

    match kind {
        ContractKind::Institution => decode_institution_slot(slot, slot_u64),
        ContractKind::ProcessTemplate => decode_template_slot(slot, slot_u64),
        ContractKind::ProcessInstance => decode_instance_slot(slot, slot_u64),
        ContractKind::BINSTDeployer => decode_deployer_slot(slot, slot_u64),
        ContractKind::Unknown => FieldChange::UnknownSlot {
            slot_hex: hex::encode(slot),
        },
    }
}

fn decode_institution_slot(slot: &[u8; 32], slot_u64: Option<u64>) -> FieldChange {
    match slot_u64 {
        Some(0) => FieldChange::InstitutionName,
        Some(1) => FieldChange::InstitutionAdmin,
        Some(2) => FieldChange::InstitutionDeployer,
        Some(3) => FieldChange::InstitutionInscriptionId,
        Some(4) => FieldChange::InstitutionRuneId,
        Some(5) => FieldChange::InstitutionBtcPubkey,
        Some(6) => FieldChange::InstitutionMembersLength,
        Some(8) => FieldChange::InstitutionProcessesLength,
        _ => {
            // Check if it's an array element
            if let Some(idx) = check_array_element(slot, storage::institution::MEMBERS_ARRAY) {
                return FieldChange::InstitutionMemberElement { index: idx };
            }
            if let Some(idx) = check_array_element(slot, storage::institution::PROCESSES_ARRAY) {
                return FieldChange::InstitutionProcessElement { index: idx };
            }
            // Could be a mapping slot (isMember)
            FieldChange::UnknownSlot {
                slot_hex: hex::encode(slot),
            }
        }
    }
}

fn decode_template_slot(slot: &[u8; 32], slot_u64: Option<u64>) -> FieldChange {
    match slot_u64 {
        Some(0) => FieldChange::TemplateName,
        Some(1) => FieldChange::TemplateDescription,
        Some(2) => FieldChange::TemplateCreator,
        Some(3) => FieldChange::TemplateStepsLength,
        Some(4) => FieldChange::TemplateInstantiationCount,
        Some(6) => FieldChange::TemplateAllInstancesLength,
        _ => {
            if let Some(idx) = check_array_element(slot, storage::template::ALL_INSTANCES_ARRAY) {
                return FieldChange::TemplateInstanceElement { index: idx };
            }
            FieldChange::UnknownSlot {
                slot_hex: hex::encode(slot),
            }
        }
    }
}

fn decode_instance_slot(slot: &[u8; 32], slot_u64: Option<u64>) -> FieldChange {
    match slot_u64 {
        Some(0) => FieldChange::InstanceTemplate,
        Some(1) => FieldChange::InstanceCreator,
        Some(2) => FieldChange::InstanceCurrentStepIndex,
        Some(3) => FieldChange::InstanceTotalSteps,
        Some(4) => FieldChange::InstanceCompleted,
        Some(5) => FieldChange::InstanceCreatedAt,
        _ => {
            // Check stepStates mapping (slot 6): keccak256(step_index ++ 6)
            for step in 0..64u64 {
                if *slot == storage::mapping_slot_uint(step, storage::instance::STEP_STATES_MAP) {
                    return FieldChange::InstanceStepState { step_index: step };
                }
            }
            FieldChange::UnknownSlot {
                slot_hex: hex::encode(slot),
            }
        }
    }
}

fn decode_deployer_slot(slot: &[u8; 32], slot_u64: Option<u64>) -> FieldChange {
    match slot_u64 {
        Some(0) => FieldChange::DeployerInstitutionsLength,
        Some(1) => FieldChange::DeployerProcessesLength,
        _ => {
            if let Some(idx) =
                check_array_element(slot, storage::deployer::INSTITUTIONS_ARRAY)
            {
                return FieldChange::DeployerInstitutionElement { index: idx };
            }
            if let Some(idx) =
                check_array_element(slot, storage::deployer::DEPLOYED_PROCESSES_ARRAY)
            {
                return FieldChange::DeployerProcessElement { index: idx };
            }
            FieldChange::UnknownSlot {
                slot_hex: hex::encode(slot),
            }
        }
    }
}

/// Try to interpret a 32-byte slot as a small u64 (top 24 bytes are zero).
fn slot_to_u64(slot: &[u8; 32]) -> Option<u64> {
    if slot[..24].iter().all(|&b| b == 0) {
        Some(u64::from_be_bytes(slot[24..32].try_into().unwrap()))
    } else {
        None
    }
}

/// Check if `slot` is an element of the dynamic array at `array_slot`.
/// Returns the element index if it matches.
fn check_array_element(slot: &[u8; 32], array_slot: u64) -> Option<u64> {
    let base = storage::array_base(array_slot);
    // slot = base + index → index = slot - base
    // Only valid if slot >= base and the difference is small
    let diff = sub_words(slot, &base)?;
    if diff < 10_000 {
        // reasonable array size
        Some(diff)
    } else {
        None
    }
}

/// Subtract two 32-byte big-endian words. Returns None if a < b.
fn sub_words(a: &[u8; 32], b: &[u8; 32]) -> Option<u64> {
    let mut borrow: i128 = 0;
    let mut result = [0u8; 32];

    for i in (0..32).rev() {
        let diff = a[i] as i128 - b[i] as i128 - borrow;
        if diff < 0 {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }

    if borrow != 0 {
        return None; // a < b
    }

    // Check that the result fits in u64 (top 24 bytes are zero)
    if result[..24].iter().all(|&b| b == 0) {
        Some(u64::from_be_bytes(result[24..32].try_into().unwrap()))
    } else {
        None // difference too large
    }
}

/// Format a field change as a human-readable string.
impl std::fmt::Display for FieldChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FieldChange::InstitutionName => write!(f, "Institution.name"),
            FieldChange::InstitutionAdmin => write!(f, "Institution.admin"),
            FieldChange::InstitutionDeployer => write!(f, "Institution.deployer"),
            FieldChange::InstitutionInscriptionId => write!(f, "Institution.inscriptionId"),
            FieldChange::InstitutionRuneId => write!(f, "Institution.runeId"),
            FieldChange::InstitutionBtcPubkey => write!(f, "Institution.btcPubkey"),
            FieldChange::InstitutionMembersLength => write!(f, "Institution.members.length"),
            FieldChange::InstitutionMemberElement { index } => {
                write!(f, "Institution.members[{index}]")
            }
            FieldChange::InstitutionIsMember { key_hint } => {
                write!(f, "Institution.isMember[{key_hint}]")
            }
            FieldChange::InstitutionProcessesLength => write!(f, "Institution.processes.length"),
            FieldChange::InstitutionProcessElement { index } => {
                write!(f, "Institution.processes[{index}]")
            }
            FieldChange::TemplateName => write!(f, "ProcessTemplate.name"),
            FieldChange::TemplateDescription => write!(f, "ProcessTemplate.description"),
            FieldChange::TemplateCreator => write!(f, "ProcessTemplate.creator"),
            FieldChange::TemplateStepsLength => write!(f, "ProcessTemplate.steps.length"),
            FieldChange::TemplateInstantiationCount => {
                write!(f, "ProcessTemplate.instantiationCount")
            }
            FieldChange::TemplateAllInstancesLength => {
                write!(f, "ProcessTemplate.allInstances.length")
            }
            FieldChange::TemplateInstanceElement { index } => {
                write!(f, "ProcessTemplate.allInstances[{index}]")
            }
            FieldChange::InstanceTemplate => write!(f, "ProcessInstance.template"),
            FieldChange::InstanceCreator => write!(f, "ProcessInstance.creator"),
            FieldChange::InstanceCurrentStepIndex => write!(f, "ProcessInstance.currentStepIndex"),
            FieldChange::InstanceTotalSteps => write!(f, "ProcessInstance.totalSteps"),
            FieldChange::InstanceCompleted => write!(f, "ProcessInstance.completed"),
            FieldChange::InstanceCreatedAt => write!(f, "ProcessInstance.createdAt"),
            FieldChange::InstanceStepState { step_index } => {
                write!(f, "ProcessInstance.stepStates[{step_index}]")
            }
            FieldChange::DeployerInstitutionsLength => {
                write!(f, "BINSTDeployer.institutions.length")
            }
            FieldChange::DeployerInstitutionElement { index } => {
                write!(f, "BINSTDeployer.institutions[{index}]")
            }
            FieldChange::DeployerProcessesLength => {
                write!(f, "BINSTDeployer.deployedProcesses.length")
            }
            FieldChange::DeployerProcessElement { index } => {
                write!(f, "BINSTDeployer.deployedProcesses[{index}]")
            }
            FieldChange::UnknownSlot { slot_hex } => write!(f, "unknown(0x{slot_hex})"),
        }
    }
}

impl std::fmt::Display for ContractKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContractKind::Institution => write!(f, "Institution"),
            ContractKind::ProcessTemplate => write!(f, "ProcessTemplate"),
            ContractKind::ProcessInstance => write!(f, "ProcessInstance"),
            ContractKind::BINSTDeployer => write!(f, "BINSTDeployer"),
            ContractKind::Unknown => write!(f, "Unknown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_to_u64_simple() {
        let mut slot = [0u8; 32];
        slot[31] = 5;
        assert_eq!(slot_to_u64(&slot), Some(5));
    }

    #[test]
    fn slot_to_u64_large() {
        let slot = [0xff; 32];
        assert_eq!(slot_to_u64(&slot), None); // top bytes non-zero
    }

    #[test]
    fn decode_institution_simple_slots() {
        let mut slot = [0u8; 32];
        slot[31] = 0;
        assert!(matches!(
            decode_slot(ContractKind::Institution, &slot),
            FieldChange::InstitutionName
        ));

        slot[31] = 5;
        assert!(matches!(
            decode_slot(ContractKind::Institution, &slot),
            FieldChange::InstitutionBtcPubkey
        ));
    }

    #[test]
    fn decode_institution_members_array_element() {
        let elem0 = storage::array_element(storage::institution::MEMBERS_ARRAY, 0);
        assert!(matches!(
            decode_slot(ContractKind::Institution, &elem0),
            FieldChange::InstitutionMemberElement { index: 0 }
        ));

        let elem3 = storage::array_element(storage::institution::MEMBERS_ARRAY, 3);
        assert!(matches!(
            decode_slot(ContractKind::Institution, &elem3),
            FieldChange::InstitutionMemberElement { index: 3 }
        ));
    }

    #[test]
    fn decode_deployer_elements() {
        let elem = storage::array_element(storage::deployer::INSTITUTIONS_ARRAY, 0);
        assert!(matches!(
            decode_slot(ContractKind::BINSTDeployer, &elem),
            FieldChange::DeployerInstitutionElement { index: 0 }
        ));
    }

    #[test]
    fn decode_instance_completed() {
        let mut slot = [0u8; 32];
        slot[31] = 4;
        assert!(matches!(
            decode_slot(ContractKind::ProcessInstance, &slot),
            FieldChange::InstanceCompleted
        ));
    }

    #[test]
    fn decode_instance_step_state() {
        let slot = storage::mapping_slot_uint(2, storage::instance::STEP_STATES_MAP);
        assert!(matches!(
            decode_slot(ContractKind::ProcessInstance, &slot),
            FieldChange::InstanceStepState { step_index: 2 }
        ));
    }

    #[test]
    fn sub_words_basic() {
        let a = storage::array_element(0, 5);
        let b = storage::array_base(0);
        assert_eq!(sub_words(&a, &b), Some(5));
    }

    #[test]
    fn sub_words_underflow() {
        let a = [0u8; 32];
        let b = [1u8; 32];
        assert_eq!(sub_words(&a, &b), None);
    }

    #[test]
    fn registry_lookup() {
        let mut reg = BinstRegistry::new();
        let addr = [0x42u8; 20];
        reg.add_institution(addr);
        assert_eq!(reg.lookup(&addr), ContractKind::Institution);
        assert_eq!(reg.lookup(&[0x00; 20]), ContractKind::Unknown);
    }

    #[test]
    fn registry_build_lookup_populates_table() {
        let mut reg = BinstRegistry::new();
        let addr = [0x42u8; 20];
        reg.add_deployer(addr);
        assert_eq!(reg.lookup_table_size(), 0);
        reg.build_lookup();
        // deployer_slots: 2 simple + 256*2 array = 514
        assert!(reg.lookup_table_size() > 0);
    }

    #[test]
    fn registry_resolves_known_slot() {
        let mut reg = BinstRegistry::new();
        let addr = [0x42u8; 20];
        reg.add_institution(addr);
        reg.build_lookup();

        // Compute the JMT hash for Institution slot 0 (name)
        let hash = jmt::evm_storage_hash_simple(&addr, 0);
        let entry = reg.resolve_storage_hash(&hash);
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.kind, ContractKind::Institution);
        assert_eq!(entry.address, addr);
        assert_eq!(slot_to_u64(&entry.slot_be), Some(0));
    }

    #[test]
    fn map_state_diff_finds_binst_entries() {
        let mut reg = BinstRegistry::new();
        let addr = [0x42u8; 20];
        reg.add_institution(addr);
        reg.build_lookup();

        // Build a fake state diff with one E/s/ entry for slot 0 (name)
        let hash = jmt::evm_storage_hash_simple(&addr, 0);
        let mut jmt_key = b"E/s/".to_vec();
        jmt_key.extend_from_slice(&hash);

        let value = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello"

        let entries = vec![
            (jmt_key, Some(value)),
            // Also add an unrelated E/H/ entry
            ({
                let mut k = b"E/H/".to_vec();
                k.extend_from_slice(&100u64.to_le_bytes());
                k
            }, Some(vec![0xFF; 32])),
        ];

        let changes = map_state_diff(&reg, &entries);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].contract, ContractKind::Institution);
        assert!(matches!(changes[0].field, FieldChange::InstitutionName));
    }

    #[test]
    fn map_state_diff_array_element() {
        let mut reg = BinstRegistry::new();
        let addr = [0x01u8; 20];
        reg.add_deployer(addr);
        reg.build_lookup();

        // BINSTDeployer.institutions[0] = array_element(0, 0)
        let slot = storage::array_element(storage::deployer::INSTITUTIONS_ARRAY, 0);
        let hash = jmt::evm_storage_hash(&addr, &slot);
        let mut jmt_key = b"E/s/".to_vec();
        jmt_key.extend_from_slice(&hash);

        let entries = vec![(jmt_key, Some(vec![0xAB; 32]))];
        let changes = map_state_diff(&reg, &entries);
        assert_eq!(changes.len(), 1);
        assert!(matches!(
            changes[0].field,
            FieldChange::DeployerInstitutionElement { index: 0 }
        ));
    }
}
