//! Solidity storage-slot computation for BINST contracts.
//!
//! The Solidity compiler assigns storage slots deterministically.  Given the
//! source-code ordering of state variables we can compute the exact slot for
//! every field, array element, and mapping entry.
//!
//! ## Conventions (Solidity ≥ 0.8, no packing optimisations for simplicity)
//!
//! | pattern                 | slot formula                                |
//! |-------------------------|---------------------------------------------|
//! | `T var` at position n   | `n`                                         |
//! | `mapping(K => V)[key]`  | `keccak256(key ++ n)`                       |
//! | `T[] arr` length        | `n`                                         |
//! | `T[] arr` element i     | `keccak256(n) + i`                          |
//! | `string s` (short ≤31B) | `n` (inline, low bit = 0)                   |
//! | `string s` (long >31B)  | len at `n`; data at `keccak256(n)` chunks   |
//!
//! ## BINST contract layouts (from source inspection)
//!
//! ### Institution.sol
//!   slot 0: name             (string)
//!   slot 1: admin            (address)
//!   slot 2: deployer         (address)
//!   slot 3: inscriptionId    (string)    — Ordinals inscription ID
//!   slot 4: runeId           (string)    — membership Rune ID
//!   slot 5: btcPubkey        (bytes32)   — Taproot x-only public key
//!   slot 6: members          (address[]) — length at 6, elements at keccak256(6)+i
//!   slot 7: isMember         (mapping(address => bool)) — keccak256(addr . 7)
//!   slot 8: processes        (address[]) — length at 8, elements at keccak256(8)+i
//!
//! ### ProcessTemplate.sol
//!   slot 0: name               (string)
//!   slot 1: description        (string)
//!   slot 2: creator            (address)
//!   slot 3: steps              (Step[])   — complex struct array
//!   slot 4: instantiationCount (uint256)
//!   slot 5: userInstances      (mapping(address => address[]))
//!   slot 6: allInstances       (address[])
//!
//! ### ProcessInstance.sol
//!   slot 0: template          (address)
//!   slot 1: creator           (address)
//!   slot 2: currentStepIndex  (uint256)
//!   slot 3: totalSteps        (uint256)
//!   slot 4: completed         (bool)
//!   slot 5: createdAt         (uint256)
//!   slot 6: stepStates        (mapping(uint256 => StepState))
//!
//! ### BINSTDeployer.sol
//!   slot 0: institutions      (address[]) — length at 0, elements at keccak256(0)+i
//!   slot 1: deployedProcesses (address[]) — length at 1, elements at keccak256(1)+i

use tiny_keccak::{Hasher, Keccak};

/// A 32-byte EVM word (storage slot key or value).
pub type Word = [u8; 32];

/// Compute Keccak-256.
pub fn keccak256(data: &[u8]) -> Word {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

/// Compute the base slot for a dynamic array at `slot`.
/// Array element `i` lives at `keccak256(slot) + i`.
pub fn array_base(slot: u64) -> Word {
    let mut buf = [0u8; 32];
    buf[24..32].copy_from_slice(&slot.to_be_bytes());
    keccak256(&buf)
}

/// Compute the storage slot for `array[index]` where the array's length
/// is at `slot`.
pub fn array_element(slot: u64, index: u64) -> Word {
    let base = array_base(slot);
    add_word_u64(base, index)
}

/// Compute the storage slot for `mapping[key]` where the mapping is at `slot`.
/// `key` is left-padded to 32 bytes.
pub fn mapping_slot(key: &[u8], slot: u64) -> Word {
    let mut buf = Vec::with_capacity(64);
    // key padded to 32 bytes
    let mut padded_key = [0u8; 32];
    let start = 32usize.saturating_sub(key.len());
    padded_key[start..].copy_from_slice(key);
    buf.extend_from_slice(&padded_key);
    // slot padded to 32 bytes
    let mut slot_bytes = [0u8; 32];
    slot_bytes[24..32].copy_from_slice(&slot.to_be_bytes());
    buf.extend_from_slice(&slot_bytes);
    keccak256(&buf)
}

/// Compute the storage slot for `mapping[uint_key]` where key is a uint256.
pub fn mapping_slot_uint(key: u64, slot: u64) -> Word {
    let mut key_bytes = [0u8; 32];
    key_bytes[24..32].copy_from_slice(&key.to_be_bytes());
    mapping_slot(&key_bytes, slot)
}

/// Add a u64 offset to a 32-byte word (big-endian).
fn add_word_u64(mut word: Word, offset: u64) -> Word {
    let mut carry = offset as u128;
    for i in (0..32).rev() {
        carry += word[i] as u128;
        word[i] = carry as u8;
        carry >>= 8;
    }
    word
}

// ── Well-known slot constants ────────────────────────────────────

/// Storage slot assignments for `Institution.sol`.
pub mod institution {
    pub const NAME: u64 = 0;
    pub const ADMIN: u64 = 1;
    pub const DEPLOYER: u64 = 2;
    pub const INSCRIPTION_ID: u64 = 3;
    pub const RUNE_ID: u64 = 4;
    pub const BTC_PUBKEY: u64 = 5;
    pub const MEMBERS_ARRAY: u64 = 6;
    pub const IS_MEMBER_MAP: u64 = 7;
    pub const PROCESSES_ARRAY: u64 = 8;
}

/// Storage slot assignments for `ProcessTemplate.sol`.
pub mod template {
    pub const NAME: u64 = 0;
    pub const DESCRIPTION: u64 = 1;
    pub const CREATOR: u64 = 2;
    pub const STEPS_ARRAY: u64 = 3;
    pub const INSTANTIATION_COUNT: u64 = 4;
    pub const USER_INSTANCES_MAP: u64 = 5;
    pub const ALL_INSTANCES_ARRAY: u64 = 6;
}

/// Storage slot assignments for `ProcessInstance.sol`.
pub mod instance {
    pub const TEMPLATE: u64 = 0;
    pub const CREATOR: u64 = 1;
    pub const CURRENT_STEP_INDEX: u64 = 2;
    pub const TOTAL_STEPS: u64 = 3;
    pub const COMPLETED: u64 = 4;
    pub const CREATED_AT: u64 = 5;
    pub const STEP_STATES_MAP: u64 = 6;
}

/// Storage slot assignments for `BINSTDeployer.sol`.
pub mod deployer {
    pub const INSTITUTIONS_ARRAY: u64 = 0;
    pub const DEPLOYED_PROCESSES_ARRAY: u64 = 1;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak256_known_vector() {
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let hash = keccak256(b"");
        assert_eq!(
            hex::encode(hash),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn array_base_slot_zero() {
        // keccak256(abi.encode(0)) — the well-known base for a dynamic array at slot 0
        // = 290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563
        let base = array_base(0);
        assert_eq!(
            hex::encode(base),
            "290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
        );
    }

    #[test]
    fn array_element_zero() {
        let base = array_base(0);
        let elem0 = array_element(0, 0);
        assert_eq!(base, elem0);
    }

    #[test]
    fn mapping_slot_address() {
        // mapping(address => bool) at slot 4, key = 0x0000...0001
        let key = [0x01u8];
        let slot = mapping_slot(&key, 4);
        assert_eq!(slot.len(), 32);
        assert_eq!(slot, mapping_slot(&key, 4));
    }

    #[test]
    fn add_word_offset() {
        let base = [0u8; 32];
        let result = add_word_u64(base, 42);
        assert_eq!(result[31], 42);
    }
}
