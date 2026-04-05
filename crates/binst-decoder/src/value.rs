//! Human-readable value decoding for BINST storage slot values.
//!
//! Raw state diff values are 32-byte EVM words (or variable-length for
//! strings). This module interprets them according to the expected Solidity
//! type for each [`FieldChange`].
//!
//! ## Supported types
//!
//! | Solidity type | Decoding |
//! |---------------|----------|
//! | `address`     | Last 20 bytes → `0x…` checksum-free hex |
//! | `uint256`     | Big-endian → decimal string |
//! | `bool`        | 0 → `false`, non-zero → `true` |
//! | `bytes32`     | Full 32 bytes → `0x…` hex |
//! | `string`      | Short (≤31 bytes): inline in slot, length = low byte / 2. |
//! |               | Long (>31 bytes): raw slot holds length; data is elsewhere. |
//! | `StepState`   | Packed struct: `status(u8) | actor(address) | timestamp(u256)` |

use crate::diff::FieldChange;

/// The expected Solidity type for a storage slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotType {
    /// `address` — 20 bytes, right-aligned in a 32-byte word.
    Address,
    /// `uint256` — 32 bytes big-endian.
    Uint256,
    /// `bool` — 0 or 1 in the last byte.
    Bool,
    /// `bytes32` — raw 32 bytes (e.g., btcPubkey).
    Bytes32,
    /// `string` — short string inline (≤31 chars) or length marker for long.
    SolString,
    /// `StepState` struct packed into mapping value slots.
    /// Layout: status(uint8) | actor(address) | data(string_ref) | timestamp(uint256)
    /// In practice the first slot of the struct contains status + actor packed.
    StepState,
}

/// A decoded, human-readable representation of a storage value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum DecodedValue {
    /// An EVM address: `0x1234abcd…` (40 hex chars).
    Address(String),
    /// A decimal number.
    Uint(String),
    /// A boolean.
    Bool(bool),
    /// Raw 32-byte hex (`0x…`).
    Bytes32(String),
    /// A short UTF-8 string decoded inline from the slot.
    String(String),
    /// A long string — we only know the byte-length from the length slot.
    /// The actual characters live in `keccak256(slot)` onwards and aren't
    /// available from a single slot value.
    LongString { byte_length: u64 },
    /// A decoded StepState struct.
    StepState {
        status: String,
        actor: String,
        timestamp: Option<String>,
    },
    /// Value was deleted (set to zero / removed from state).
    Deleted,
    /// We couldn't decode — fall back to raw hex.
    RawHex(String),
}

impl std::fmt::Display for DecodedValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodedValue::Address(a) => write!(f, "{a}"),
            DecodedValue::Uint(n) => write!(f, "{n}"),
            DecodedValue::Bool(b) => write!(f, "{b}"),
            DecodedValue::Bytes32(h) => write!(f, "{h}"),
            DecodedValue::String(s) => write!(f, "\"{s}\""),
            DecodedValue::LongString { byte_length } => {
                write!(f, "<string, {byte_length} bytes>")
            }
            DecodedValue::StepState {
                status,
                actor,
                timestamp,
            } => {
                write!(f, "{status} by {actor}")?;
                if let Some(ts) = timestamp {
                    write!(f, " at {ts}")?;
                }
                Ok(())
            }
            DecodedValue::Deleted => write!(f, "DELETED"),
            DecodedValue::RawHex(h) => write!(f, "0x{h}"),
        }
    }
}

/// Return the expected Solidity type for a given field.
pub fn field_type(field: &FieldChange) -> SlotType {
    match field {
        // ── Institution ──
        FieldChange::InstitutionName => SlotType::SolString,
        FieldChange::InstitutionAdmin => SlotType::Address,
        FieldChange::InstitutionDeployer => SlotType::Address,
        FieldChange::InstitutionInscriptionId => SlotType::SolString,
        FieldChange::InstitutionRuneId => SlotType::SolString,
        FieldChange::InstitutionBtcPubkey => SlotType::Bytes32,
        FieldChange::InstitutionMembersLength => SlotType::Uint256,
        FieldChange::InstitutionMemberElement { .. } => SlotType::Address,
        FieldChange::InstitutionIsMember { .. } => SlotType::Bool,
        FieldChange::InstitutionProcessesLength => SlotType::Uint256,
        FieldChange::InstitutionProcessElement { .. } => SlotType::Address,

        // ── ProcessTemplate ──
        FieldChange::TemplateName => SlotType::SolString,
        FieldChange::TemplateDescription => SlotType::SolString,
        FieldChange::TemplateCreator => SlotType::Address,
        FieldChange::TemplateStepsLength => SlotType::Uint256,
        FieldChange::TemplateInstantiationCount => SlotType::Uint256,
        FieldChange::TemplateAllInstancesLength => SlotType::Uint256,
        FieldChange::TemplateInstanceElement { .. } => SlotType::Address,

        // ── ProcessInstance ──
        FieldChange::InstanceTemplate => SlotType::Address,
        FieldChange::InstanceCreator => SlotType::Address,
        FieldChange::InstanceCurrentStepIndex => SlotType::Uint256,
        FieldChange::InstanceTotalSteps => SlotType::Uint256,
        FieldChange::InstanceCompleted => SlotType::Bool,
        FieldChange::InstanceCreatedAt => SlotType::Uint256,
        FieldChange::InstanceStepState { .. } => SlotType::StepState,

        // ── BINSTDeployer ──
        FieldChange::DeployerInstitutionsLength => SlotType::Uint256,
        FieldChange::DeployerInstitutionElement { .. } => SlotType::Address,
        FieldChange::DeployerProcessesLength => SlotType::Uint256,
        FieldChange::DeployerProcessElement { .. } => SlotType::Address,

        // ── Unknown ──
        FieldChange::UnknownSlot { .. } => SlotType::Bytes32,
    }
}

/// Decode a raw hex value string according to the expected Solidity type.
///
/// `raw_hex` is the value as produced by the state diff — a hex string
/// (without `0x` prefix) representing the EVM storage word(s).
///
/// **Important:** Citrea / Sovereign SDK stores EVM storage values in
/// little-endian word order, so the entire 32-byte word is byte-reversed
/// compared to the standard Solidity ABI encoding. This function reverses
/// the bytes before decoding.
///
/// Returns a [`DecodedValue`] with a human-readable representation.
pub fn decode_value(field: &FieldChange, raw_hex: Option<&str>) -> DecodedValue {
    let Some(hex_str) = raw_hex else {
        return DecodedValue::Deleted;
    };

    if hex_str.is_empty() {
        return DecodedValue::Deleted;
    }

    let Ok(bytes) = hex::decode(hex_str) else {
        return DecodedValue::RawHex(hex_str.to_string());
    };

    // Citrea stores EVM slot values in little-endian word order.
    // The state diff may trim trailing zero bytes (from the LE end),
    // so we right-pad to 32 bytes first, then reverse to get the
    // standard Solidity big-endian layout.
    let mut le_word = [0u8; 32];
    let len = bytes.len().min(32);
    le_word[..len].copy_from_slice(&bytes[..len]);
    le_word.reverse();

    let slot_type = field_type(field);
    decode_bytes(slot_type, &le_word)
}

/// Decode raw bytes according to the given slot type.
fn decode_bytes(slot_type: SlotType, bytes: &[u8]) -> DecodedValue {
    match slot_type {
        SlotType::Address => decode_address(bytes),
        SlotType::Uint256 => decode_uint256(bytes),
        SlotType::Bool => decode_bool(bytes),
        SlotType::Bytes32 => decode_bytes32(bytes),
        SlotType::SolString => decode_sol_string(bytes),
        SlotType::StepState => decode_step_state(bytes),
    }
}

/// Decode an address from a 32-byte word (last 20 bytes).
fn decode_address(bytes: &[u8]) -> DecodedValue {
    if bytes.len() < 20 {
        return DecodedValue::RawHex(hex::encode(bytes));
    }
    // Address is right-aligned: last 20 bytes of a 32-byte word
    let start = bytes.len().saturating_sub(20);
    // But check if the leading bytes are zeros (valid address padding)
    let addr_bytes = &bytes[start..];
    DecodedValue::Address(format!("0x{}", hex::encode(addr_bytes)))
}

/// Decode a uint256 from big-endian bytes.
fn decode_uint256(bytes: &[u8]) -> DecodedValue {
    // Strip leading zeros
    let stripped = match bytes.iter().position(|&b| b != 0) {
        Some(pos) => &bytes[pos..],
        None => return DecodedValue::Uint("0".to_string()),
    };

    // For values that fit in u128, decode normally
    if stripped.len() <= 16 {
        let mut buf = [0u8; 16];
        buf[16 - stripped.len()..].copy_from_slice(stripped);
        let val = u128::from_be_bytes(buf);
        return DecodedValue::Uint(val.to_string());
    }

    // For very large numbers, show hex
    DecodedValue::Uint(format!("0x{}", hex::encode(bytes)))
}

/// Decode a bool (0 = false, non-zero = true).
fn decode_bool(bytes: &[u8]) -> DecodedValue {
    let is_true = bytes.iter().any(|&b| b != 0);
    DecodedValue::Bool(is_true)
}

/// Decode a bytes32 value.
fn decode_bytes32(bytes: &[u8]) -> DecodedValue {
    DecodedValue::Bytes32(format!("0x{}", hex::encode(bytes)))
}

/// Decode a Solidity string from a storage slot.
///
/// Short strings (≤31 bytes): the low bit of the slot is 0, and the
/// string data is stored inline in the high bytes. The length in bytes
/// is `slot_value[31] / 2` (the low byte divided by 2).
///
/// Long strings (>31 bytes): the low bit is 1, and the slot stores
/// `length * 2 + 1`. The actual data lives at `keccak256(slot_number)`.
fn decode_sol_string(bytes: &[u8]) -> DecodedValue {
    if bytes.is_empty() {
        return DecodedValue::String(String::new());
    }

    // Pad to 32 bytes if shorter (state diffs may be trimmed)
    let mut word = [0u8; 32];
    let len = bytes.len().min(32);
    // Right-align: last `len` bytes
    word[32 - len..].copy_from_slice(&bytes[..len]);

    let low_byte = word[31];

    if low_byte & 1 == 0 {
        // Short string: length = low_byte / 2
        let str_len = (low_byte / 2) as usize;
        if str_len > 31 {
            return DecodedValue::RawHex(hex::encode(bytes));
        }
        let str_bytes = &word[..str_len];
        match std::str::from_utf8(str_bytes) {
            Ok(s) => DecodedValue::String(s.to_string()),
            Err(_) => DecodedValue::RawHex(hex::encode(bytes)),
        }
    } else {
        // Long string: slot stores (length * 2 + 1)
        // Decode the full 32-byte word as a uint256
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&word[16..32]);
        let encoded = u128::from_be_bytes(buf);
        let byte_length = (encoded - 1) / 2;
        DecodedValue::LongString {
            byte_length: byte_length as u64,
        }
    }
}

/// Decode a StepState struct from its first mapping slot.
///
/// Solidity struct `StepState { StepStatus status; address actor; string data; uint256 timestamp; }`
///
/// In a mapping, each struct occupies consecutive slots starting from
/// `keccak256(key . slot)`:
///   - slot+0: status (uint8, packed as uint256)
///   - slot+1: actor (address)  
///   - slot+2: data (string — just the length/pointer slot)
///   - slot+3: timestamp (uint256)
///
/// Solidity packs `status` (uint8, 1 byte) + `actor` (address, 20 bytes)
/// right-aligned into the same 32-byte slot:
///
///   BE word: `[00 × 11][actor × 20][status × 1]`
///
/// Status occupies the lowest byte (byte 31), and the 20-byte actor sits
/// just above it (bytes 11..31).
///
/// After the Citrea LE→BE word reversal performed by `decode_value`, the
/// bytes are in standard Solidity layout, so we read directly.
fn decode_step_state(bytes: &[u8]) -> DecodedValue {
    if bytes.len() < 21 {
        return DecodedValue::RawHex(hex::encode(bytes));
    }

    let mut word = [0u8; 32];
    let len = bytes.len().min(32);
    word[32 - len..].copy_from_slice(&bytes[..len]);

    // Packed layout (standard Solidity BE after LE reversal):
    //   word[31]     = status (uint8)
    //   word[11..31] = actor address (20 bytes, canonical order)
    let status_byte = word[31];
    let status = match status_byte {
        0 => "Pending",
        1 => "Completed",
        2 => "Rejected",
        _ => "Unknown",
    };

    let actor = format!("0x{}", hex::encode(&word[11..31]));

    DecodedValue::StepState {
        status: status.to_string(),
        actor,
        timestamp: None, // timestamp is in a separate slot (base+3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_address_from_word() {
        // 32-byte word with address in last 20 bytes
        let mut word = [0u8; 32];
        word[12..32].copy_from_slice(&[0x8C, 0xF6, 0xfe, 0x5c, 0xd0, 0x90, 0x5b, 0x6b,
            0xFb, 0x81, 0x64, 0x3b, 0x0D, 0xCd, 0xa6, 0x4A, 0xf3, 0x2f, 0xd7, 0x62]);
        let decoded = decode_bytes(SlotType::Address, &word);
        assert_eq!(
            decoded,
            DecodedValue::Address("0x8cf6fe5cd0905b6bfb81643b0dcda64af32fd762".to_string())
        );
        assert_eq!(decoded.to_string(), "0x8cf6fe5cd0905b6bfb81643b0dcda64af32fd762");
    }

    #[test]
    fn decode_uint256_small() {
        let mut word = [0u8; 32];
        word[31] = 4;
        let decoded = decode_bytes(SlotType::Uint256, &word);
        assert_eq!(decoded, DecodedValue::Uint("4".to_string()));
        assert_eq!(decoded.to_string(), "4");
    }

    #[test]
    fn decode_uint256_zero() {
        let word = [0u8; 32];
        let decoded = decode_bytes(SlotType::Uint256, &word);
        assert_eq!(decoded, DecodedValue::Uint("0".to_string()));
    }

    #[test]
    fn decode_uint256_timestamp() {
        // Example: 1710597952 = 0x65F5A740
        let mut word = [0u8; 32];
        word[28] = 0x65;
        word[29] = 0xF5;
        word[30] = 0xA7;
        word[31] = 0x40;
        let decoded = decode_bytes(SlotType::Uint256, &word);
        assert_eq!(decoded, DecodedValue::Uint("1710597952".to_string()));
    }

    #[test]
    fn decode_bool_true() {
        let mut word = [0u8; 32];
        word[31] = 1;
        let decoded = decode_bytes(SlotType::Bool, &word);
        assert_eq!(decoded, DecodedValue::Bool(true));
        assert_eq!(decoded.to_string(), "true");
    }

    #[test]
    fn decode_bool_false() {
        let word = [0u8; 32];
        let decoded = decode_bytes(SlotType::Bool, &word);
        assert_eq!(decoded, DecodedValue::Bool(false));
        assert_eq!(decoded.to_string(), "false");
    }

    #[test]
    fn decode_bytes32_pubkey() {
        let mut word = [0u8; 32];
        word[0] = 0x79;
        word[1] = 0xbe;
        word[31] = 0x98;
        let decoded = decode_bytes(SlotType::Bytes32, &word);
        assert!(matches!(decoded, DecodedValue::Bytes32(_)));
        assert!(decoded.to_string().starts_with("0x79be"));
    }

    #[test]
    fn decode_short_string() {
        // "Hello" encoded as a short Solidity string in a 32-byte slot:
        // bytes 0..4 = "Hello", byte 31 = 5*2 = 10 (length * 2)
        let mut word = [0u8; 32];
        word[0] = b'H';
        word[1] = b'e';
        word[2] = b'l';
        word[3] = b'l';
        word[4] = b'o';
        word[31] = 10; // 5 chars * 2 = 10
        let decoded = decode_bytes(SlotType::SolString, &word);
        assert_eq!(decoded, DecodedValue::String("Hello".to_string()));
        assert_eq!(decoded.to_string(), "\"Hello\"");
    }

    #[test]
    fn decode_short_string_empty() {
        let word = [0u8; 32];
        let decoded = decode_bytes(SlotType::SolString, &word);
        assert_eq!(decoded, DecodedValue::String(String::new()));
    }

    #[test]
    fn decode_long_string() {
        // Long string: low bit = 1, value = length * 2 + 1
        // E.g., a 125-byte string: slot = 125 * 2 + 1 = 251 = 0xFB
        let mut word = [0u8; 32];
        word[31] = 0xFB; // 251 = 125*2 + 1
        let decoded = decode_bytes(SlotType::SolString, &word);
        assert_eq!(
            decoded,
            DecodedValue::LongString { byte_length: 125 }
        );
        assert_eq!(decoded.to_string(), "<string, 125 bytes>");
    }

    #[test]
    fn decode_step_state_completed() {
        // StepState in standard Solidity BE layout (as produced by LE→BE reversal):
        //   word[31]     = status = 1 (Completed)
        //   word[11..31] = actor  = 0x8CF6fe5cd0905b6bFb81643b0DCda64Af32fd762
        let mut word = [0u8; 32];
        word[31] = 1; // Completed
        word[11..31].copy_from_slice(&[
            0x8C, 0xF6, 0xfe, 0x5c, 0xd0, 0x90, 0x5b, 0x6b,
            0xFb, 0x81, 0x64, 0x3b, 0x0D, 0xCd, 0xa6, 0x4A,
            0xf3, 0x2f, 0xd7, 0x62,
        ]);
        let decoded = decode_bytes(SlotType::StepState, &word);
        match &decoded {
            DecodedValue::StepState { status, actor, .. } => {
                assert_eq!(status, "Completed");
                assert_eq!(actor, "0x8cf6fe5cd0905b6bfb81643b0dcda64af32fd762");
            }
            _ => panic!("Expected StepState, got {decoded:?}"),
        }
        assert!(decoded.to_string().contains("Completed"));
    }

    #[test]
    fn decode_value_deleted() {
        let decoded = decode_value(&FieldChange::InstitutionName, None);
        assert_eq!(decoded, DecodedValue::Deleted);
        assert_eq!(decoded.to_string(), "DELETED");
    }

    #[test]
    fn decode_value_from_hex() {
        // Institution.admin = address in Citrea LE word order.
        // The address 0x8cf6fe5cd0905b6bfb81643b0dcda64af32fd762 is stored
        // as the byte-reversed 32-byte word in the Citrea state trie.
        let hex = "62d72ff34aa6cd0d3b6481fb6b5b90d05cfef68c000000000000000000000000";
        let decoded = decode_value(&FieldChange::InstitutionAdmin, Some(hex));
        assert_eq!(
            decoded,
            DecodedValue::Address("0x8cf6fe5cd0905b6bfb81643b0dcda64af32fd762".to_string())
        );
    }

    #[test]
    fn field_type_coverage() {
        // Ensure every FieldChange variant has a type mapping
        assert_eq!(field_type(&FieldChange::InstitutionName), SlotType::SolString);
        assert_eq!(field_type(&FieldChange::InstitutionAdmin), SlotType::Address);
        assert_eq!(field_type(&FieldChange::InstanceCompleted), SlotType::Bool);
        assert_eq!(field_type(&FieldChange::InstitutionBtcPubkey), SlotType::Bytes32);
        assert_eq!(field_type(&FieldChange::InstanceCreatedAt), SlotType::Uint256);
        assert_eq!(field_type(&FieldChange::InstanceStepState { step_index: 0 }), SlotType::StepState);
    }
}
