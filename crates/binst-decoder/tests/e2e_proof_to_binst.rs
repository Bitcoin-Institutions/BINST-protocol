//! End-to-end integration test: full pipeline from batch proof → BINST state changes.
//!
//! Simulates the real Citrea pipeline:
//! 1. Create a `BatchProofCircuitOutputV3` with BINST-like state diffs
//! 2. Borsh-serialize → embed in a fake RISC Zero receipt → Brotli-compress
//! 3. Decompress → extract journal → decode → map to BINST fields
//!
//! This validates that the complete chain works end-to-end without a live
//! Bitcoin node.

use binst_decoder::diff::{BinstRegistry, ContractKind, FieldChange, decode_slot};
use binst_decoder::storage;
use citrea_decoder::proof::{
    BatchProofCircuitOutput, BatchProofCircuitOutputV3, decode_complete_proof,
};

/// Build a fake "receipt" containing the journal, mimicking how bincode
/// serializes a Vec<u8> inside a RISC Zero InnerReceipt.
fn wrap_journal_in_fake_receipt(journal: &[u8]) -> Vec<u8> {
    let mut receipt = Vec::new();

    // Simulate bincode's InnerReceipt::Fake variant (tag = 3)
    receipt.extend_from_slice(&3u32.to_le_bytes());

    // FakeReceipt { claim: MaybePruned::Value(ReceiptClaim) }
    // MaybePruned::Value = variant 0
    receipt.extend_from_slice(&0u32.to_le_bytes());

    // ReceiptClaim has several fields before output. Add some plausible padding.
    // pre: MaybePruned<SystemState> — fake some bytes
    receipt.extend_from_slice(&[0u8; 128]);

    // The journal is wrapped in MaybePruned<Vec<u8>> inside Output inside
    // MaybePruned<Option<Output>>. In bincode, the journal Vec<u8> has a
    // u64 length prefix. This is what our heuristic scanner looks for.
    receipt.extend_from_slice(&(journal.len() as u64).to_le_bytes());
    receipt.extend_from_slice(journal);

    // Some trailing data (assumptions, etc.)
    receipt.extend_from_slice(&[0u8; 64]);

    receipt
}

/// Brotli-compress data with the same parameters Citrea uses.
fn brotli_compress(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut writer = brotli::CompressorWriter::new(Vec::new(), 4096, 11, 22);
    writer.write_all(data).unwrap();
    writer.into_inner()
}

/// Helper: create a 32-byte slot key with a small integer value.
fn slot_key(n: u64) -> Vec<u8> {
    let mut key = vec![0u8; 32];
    key[24..32].copy_from_slice(&n.to_be_bytes());
    key
}

/// Helper: create a 32-byte value containing an address at the low 20 bytes.
fn address_value(addr: [u8; 20]) -> Vec<u8> {
    let mut val = vec![0u8; 32];
    val[12..32].copy_from_slice(&addr);
    val
}

#[test]
fn full_pipeline_institution_creation() {
    // ── Step 1: Build realistic state diff for an Institution creation ──
    //
    // When `createInstitution("ACME Corp", btcPubkey)` is called:
    //   - BINSTDeployer slot 0 (institutions.length) → 1
    //   - BINSTDeployer keccak256(0)+0 (institutions[0]) → institution_addr
    //   - Institution slot 0 (name) → "ACME Corp"
    //   - Institution slot 1 (admin) → caller
    //   - Institution slot 2 (deployer) → deployer_addr
    //   - Institution slot 5 (btcPubkey) → pubkey

    let deployer_addr = [0x11u8; 20];
    let institution_addr = [0x22u8; 20];
    let caller_addr = [0x33u8; 20];
    let btc_pubkey = [0xaa; 32];

    let state_diff = vec![
        // BINSTDeployer: institutions.length = 1
        (slot_key(0), Some(slot_key(1))),
        // BINSTDeployer: institutions[0] = institution_addr
        (storage::array_element(0, 0).to_vec(), Some(address_value(institution_addr))),
        // Institution: name = "ACME Corp" (short string, inline in slot)
        (slot_key(0), Some(vec![0u8; 32])), // simplified
        // Institution: admin = caller
        (slot_key(1), Some(address_value(caller_addr))),
        // Institution: deployer = deployer_addr
        (slot_key(2), Some(address_value(deployer_addr))),
        // Institution: btcPubkey
        (slot_key(5), Some(btc_pubkey.to_vec())),
    ];

    let output = BatchProofCircuitOutputV3 {
        state_roots: vec![[0xaa; 32], [0xbb; 32]],
        final_l2_block_hash: [0xcc; 32],
        state_diff,
        last_l2_height: 500,
        sequencer_commitment_hashes: vec![[0xdd; 32]],
        sequencer_commitment_index_range: (10, 10),
        last_l1_hash_on_bitcoin_light_client_contract: [0xee; 32],
        previous_commitment_index: Some(9),
        previous_commitment_hash: Some([0xff; 32]),
    };

    // ── Step 2: Encode → fake receipt → compress ──

    let journal = borsh::to_vec(&BatchProofCircuitOutput::V3(output)).unwrap();
    let fake_receipt = wrap_journal_in_fake_receipt(&journal);
    let compressed = brotli_compress(&fake_receipt);

    // ── Step 3: Decode back (this is what `decode_complete_proof` does) ──

    let decoded = decode_complete_proof(&compressed)
        .expect("full pipeline decode should succeed");

    assert_eq!(decoded.last_l2_height(), 500);
    assert_eq!(decoded.state_roots().len(), 2);
    assert_eq!(decoded.commitment_range(), (10, 10));
    assert_eq!(decoded.state_diff_len(), 6);

    // ── Step 4: Map state diffs to BINST fields ──

    let mut registry = BinstRegistry::new();
    registry.add_deployer(deployer_addr);
    registry.add_institution(institution_addr);

    // Test deployer slot decoding
    let deployer_length_slot: [u8; 32] = slot_key(0).try_into().unwrap();
    let field = decode_slot(ContractKind::BINSTDeployer, &deployer_length_slot);
    assert!(
        matches!(field, FieldChange::DeployerInstitutionsLength),
        "slot 0 on deployer should be institutions.length, got {field}"
    );

    let deployer_elem_slot = storage::array_element(0, 0);
    let field = decode_slot(ContractKind::BINSTDeployer, &deployer_elem_slot);
    assert!(
        matches!(field, FieldChange::DeployerInstitutionElement { index: 0 }),
        "keccak256(0)+0 on deployer should be institutions[0], got {field}"
    );

    // Test institution slot decoding
    let name_slot: [u8; 32] = slot_key(0).try_into().unwrap();
    let field = decode_slot(ContractKind::Institution, &name_slot);
    assert!(
        matches!(field, FieldChange::InstitutionName),
        "slot 0 on institution should be name, got {field}"
    );

    let admin_slot: [u8; 32] = slot_key(1).try_into().unwrap();
    let field = decode_slot(ContractKind::Institution, &admin_slot);
    assert!(
        matches!(field, FieldChange::InstitutionAdmin),
        "slot 1 on institution should be admin, got {field}"
    );

    let pubkey_slot: [u8; 32] = slot_key(5).try_into().unwrap();
    let field = decode_slot(ContractKind::Institution, &pubkey_slot);
    assert!(
        matches!(field, FieldChange::InstitutionBtcPubkey),
        "slot 5 on institution should be btcPubkey, got {field}"
    );

    // Verify Display output
    assert_eq!(
        format!("{}", decode_slot(ContractKind::Institution, &name_slot)),
        "Institution.name"
    );
    assert_eq!(
        format!("{}", decode_slot(ContractKind::BINSTDeployer, &deployer_elem_slot)),
        "BINSTDeployer.institutions[0]"
    );
}

#[test]
fn full_pipeline_process_advancement() {
    // Simulate a ProcessInstance advancing a step:
    //   - Instance slot 2 (currentStepIndex) → 1
    //   - Template slot 4 (instantiationCount) stays or increments

    let state_diff = vec![
        // ProcessInstance: currentStepIndex = 1
        (slot_key(2), Some(slot_key(1))),
        // ProcessInstance: completed still false
        (slot_key(4), Some(slot_key(0))),
    ];

    let output = BatchProofCircuitOutputV3 {
        state_roots: vec![[0x11; 32], [0x22; 32]],
        final_l2_block_hash: [0x33; 32],
        state_diff,
        last_l2_height: 1000,
        sequencer_commitment_hashes: vec![[0x44; 32]],
        sequencer_commitment_index_range: (20, 20),
        last_l1_hash_on_bitcoin_light_client_contract: [0x55; 32],
        previous_commitment_index: None,
        previous_commitment_hash: None,
    };

    let journal = borsh::to_vec(&BatchProofCircuitOutput::V3(output)).unwrap();
    let fake_receipt = wrap_journal_in_fake_receipt(&journal);
    let compressed = brotli_compress(&fake_receipt);

    let decoded = decode_complete_proof(&compressed).unwrap();

    assert_eq!(decoded.last_l2_height(), 1000);
    assert_eq!(decoded.state_diff_len(), 2);

    // Verify the state diff entries map correctly
    let step_slot: [u8; 32] = slot_key(2).try_into().unwrap();
    assert!(matches!(
        decode_slot(ContractKind::ProcessInstance, &step_slot),
        FieldChange::InstanceCurrentStepIndex
    ));

    let completed_slot: [u8; 32] = slot_key(4).try_into().unwrap();
    assert!(matches!(
        decode_slot(ContractKind::ProcessInstance, &completed_slot),
        FieldChange::InstanceCompleted
    ));
}

#[test]
fn full_pipeline_empty_state_diff() {
    // A batch proof covering blocks with no BINST-relevant changes
    let output = BatchProofCircuitOutputV3 {
        state_roots: vec![[0x00; 32]],
        final_l2_block_hash: [0x00; 32],
        state_diff: vec![],
        last_l2_height: 42,
        sequencer_commitment_hashes: vec![],
        sequencer_commitment_index_range: (0, 0),
        last_l1_hash_on_bitcoin_light_client_contract: [0x00; 32],
        previous_commitment_index: None,
        previous_commitment_hash: None,
    };

    let journal = borsh::to_vec(&BatchProofCircuitOutput::V3(output)).unwrap();
    let fake_receipt = wrap_journal_in_fake_receipt(&journal);
    let compressed = brotli_compress(&fake_receipt);

    let decoded = decode_complete_proof(&compressed).unwrap();
    assert_eq!(decoded.last_l2_height(), 42);
    assert_eq!(decoded.state_diff_len(), 0);
}

#[test]
fn full_pipeline_large_state_diff() {
    // Simulate a large batch proof with many state diff entries
    // (e.g., many process instances being created in one batch)
    let mut state_diff = Vec::new();
    for i in 0..500u64 {
        state_diff.push((slot_key(i), Some(slot_key(i + 1))));
    }

    let output = BatchProofCircuitOutputV3 {
        state_roots: vec![[1u8; 32]; 10],
        final_l2_block_hash: [2u8; 32],
        state_diff,
        last_l2_height: 9999,
        sequencer_commitment_hashes: vec![[3u8; 32]; 5],
        sequencer_commitment_index_range: (100, 104),
        last_l1_hash_on_bitcoin_light_client_contract: [4u8; 32],
        previous_commitment_index: Some(99),
        previous_commitment_hash: Some([5u8; 32]),
    };

    let journal = borsh::to_vec(&BatchProofCircuitOutput::V3(output)).unwrap();
    let fake_receipt = wrap_journal_in_fake_receipt(&journal);
    let compressed = brotli_compress(&fake_receipt);

    let decoded = decode_complete_proof(&compressed).unwrap();
    assert_eq!(decoded.last_l2_height(), 9999);
    assert_eq!(decoded.state_diff_len(), 500);
    assert_eq!(decoded.state_roots().len(), 10);
    assert_eq!(decoded.commitment_range(), (100, 104));
}

#[test]
fn registry_filters_relevant_changes() {
    // Verify that the registry correctly distinguishes BINST contracts from
    // other Citrea state changes (system contracts, ERC20s, etc.)
    let mut registry = BinstRegistry::new();
    let deployer = [0x01; 20];
    let institution = [0x02; 20];
    let template = [0x03; 20];
    let instance = [0x04; 20];
    let random = [0x99; 20];

    registry.add_deployer(deployer);
    registry.add_institution(institution);
    registry.add_template(template);
    registry.add_instance(instance);

    assert_eq!(registry.len(), 4);
    assert!(registry.contains(&deployer));
    assert!(registry.contains(&institution));
    assert!(!registry.contains(&random));

    assert_eq!(registry.lookup(&deployer), ContractKind::BINSTDeployer);
    assert_eq!(registry.lookup(&institution), ContractKind::Institution);
    assert_eq!(registry.lookup(&template), ContractKind::ProcessTemplate);
    assert_eq!(registry.lookup(&instance), ContractKind::ProcessInstance);
    assert_eq!(registry.lookup(&random), ContractKind::Unknown);
}
