//! Pure ABI encoding/decoding for BINST smart contracts.
//!
//! No I/O, no async, no feature gates — works everywhere.
//! Ported from `webapp/binst-pilot-webapp/src/citrea.rs`.

use crate::selectors;

// ── Encoding primitives ──────────────────────────────────────────

/// ABI-encode a `uint256` as a 32-byte hex word (no `0x` prefix).
pub fn encode_uint256(v: u64) -> String {
    format!("{:064x}", v)
}

/// ABI-encode a `uint8` as a 32-byte hex word (no `0x` prefix).
pub fn encode_uint8(v: u8) -> String {
    format!("{:064x}", v)
}

/// ABI-encode an `address` as a 32-byte hex word (no `0x` prefix).
/// Input can be with or without `0x` prefix.
pub fn encode_address(addr: &str) -> String {
    let clean = addr.strip_prefix("0x").unwrap_or(addr).to_lowercase();
    format!("{:0>64}", clean)
}

/// ABI-encode a `string` value (length-prefixed, padded to 32 bytes).
/// Returns hex without `0x` prefix.
pub fn encode_string(s: &str) -> String {
    let bytes = s.as_bytes();
    let len = bytes.len();
    // length word
    let mut hex = format!("{:064x}", len);
    // data words (padded to 32-byte boundary)
    for chunk in bytes.chunks(32) {
        let mut word = String::with_capacity(64);
        for b in chunk {
            word.push_str(&format!("{:02x}", b));
        }
        // Right-pad to 64 hex chars (32 bytes)
        while word.len() < 64 {
            word.push('0');
        }
        hex.push_str(&word);
    }
    // Handle empty string — still need one padded word of zeros
    if bytes.is_empty() {
        hex.push_str(&"0".repeat(64));
    }
    hex
}

/// ABI-encode a `string[]` array.
///
/// Layout:
/// ```text
///   word 0: array length
///   word 1..N: offsets to each string (relative to start of array data)
///   then: encoded strings one after another
/// ```
pub fn encode_string_array(strings: &[String]) -> String {
    let n = strings.len();

    // Encode each string individually
    let encoded_strings: Vec<String> = strings.iter().map(|s| encode_string(s)).collect();

    // The offsets area starts after: N offset words (N * 32 bytes)
    let data_area_start = n * 32;

    let mut cumulative_offset = data_area_start;
    let mut offset_words = String::new();
    let mut data_section = String::new();

    for encoded in &encoded_strings {
        offset_words.push_str(&format!("{:064x}", cumulative_offset));
        data_section.push_str(encoded);
        cumulative_offset += encoded.len() / 2; // hex chars / 2 = bytes
    }

    let mut result = format!("{:064x}", n); // array length
    result.push_str(&offset_words);
    result.push_str(&data_section);
    result
}

// ── Decoding primitives ──────────────────────────────────────────

/// Decode a `uint256` from a 64-char hex word.
pub fn decode_uint256(hex_word: &str) -> Result<u64, String> {
    u64::from_str_radix(hex_word.strip_prefix("0x").unwrap_or(hex_word), 16)
        .map_err(|e| format!("decode_uint256: {e}"))
}

/// Decode a `bool` from a 64-char hex word (last nibble).
pub fn decode_bool(hex_word: &str) -> Result<bool, String> {
    let v = decode_uint256(hex_word)?;
    Ok(v != 0)
}

/// Decode an `address` from a 32-byte padded hex word.
pub fn decode_address(hex_word: &str) -> String {
    let clean = hex_word.strip_prefix("0x").unwrap_or(hex_word);
    format!("0x{}", &clean[24..])
}

/// Decode an ABI-encoded `string` from raw hex data (no `0x` prefix).
/// `data` starts at the string's offset position (length word first).
pub fn decode_string(data: &str) -> Result<String, String> {
    if data.len() < 64 {
        return Err("decode_string: data too short for length word".to_string());
    }
    let length = usize::from_str_radix(&data[0..64], 16)
        .map_err(|e| format!("decode_string length: {e}"))?;
    let hex_bytes = &data[64..64 + length * 2];
    let bytes = hex::decode(hex_bytes)
        .map_err(|e| format!("decode_string hex: {e}"))?;
    String::from_utf8(bytes)
        .map_err(|e| format!("decode_string utf8: {e}"))
}

// ── High-level calldata builders ─────────────────────────────────

/// Encode calldata for `BINSTProcessFactory.createInstance(string,string[],string[])`.
///
/// Returns hex string with `0x` prefix.
pub fn encode_create_instance(
    template_inscription_id: &str,
    step_names: &[String],
    step_action_types: &[String],
) -> Result<String, String> {
    let selector = hex::encode(selectors::CREATE_INSTANCE);

    // Head: 3 words (3 offsets) = 96 bytes
    let head_size: usize = 3 * 32;

    let encoded_template_id = encode_string(template_inscription_id);
    let encoded_step_names = encode_string_array(step_names);
    let encoded_step_action_types = encode_string_array(step_action_types);

    let offset0 = head_size;
    let offset1 = offset0 + encoded_template_id.len() / 2;
    let offset2 = offset1 + encoded_step_names.len() / 2;

    let mut calldata = String::with_capacity(
        2 + 8 + 192
            + encoded_template_id.len()
            + encoded_step_names.len()
            + encoded_step_action_types.len(),
    );
    calldata.push_str("0x");
    calldata.push_str(&selector);
    calldata.push_str(&format!("{:064x}", offset0));
    calldata.push_str(&format!("{:064x}", offset1));
    calldata.push_str(&format!("{:064x}", offset2));
    calldata.push_str(&encoded_template_id);
    calldata.push_str(&encoded_step_names);
    calldata.push_str(&encoded_step_action_types);

    Ok(calldata)
}

/// Encode calldata for `BINSTProcess.executeStep(uint8 status, string data)`.
///
/// Returns hex string with `0x` prefix.
pub fn encode_execute_step(status: u8, data: &str) -> String {
    let selector = hex::encode(selectors::EXECUTE_STEP);
    // uint8 status
    let status_word = encode_uint8(status);
    // offset to string data (2 * 32 = 64 bytes = 0x40)
    let offset = encode_uint256(64);
    // encoded string
    let encoded_data = encode_string(data);

    format!("0x{selector}{status_word}{offset}{encoded_data}")
}

/// Encode calldata for `getTemplateInstances(string)`.
///
/// Returns hex string with `0x` prefix.
pub fn encode_get_template_instances(template_inscription_id: &str) -> String {
    let selector = hex::encode(selectors::GET_TEMPLATE_INSTANCES);
    // Single dynamic param: offset = 32 (0x20)
    let offset = encode_uint256(32);
    let encoded_id = encode_string(template_inscription_id);
    format!("0x{selector}{offset}{encoded_id}")
}

/// Encode a simple no-args call (e.g. `getInstanceCount()`, `totalSteps()`).
///
/// Returns hex string with `0x` prefix.
pub fn encode_no_args(selector: &[u8; 4]) -> String {
    format!("0x{}", hex::encode(selector))
}

/// Encode a single `uint256` arg call (e.g. `allInstances(0)`, `getStep(2)`).
///
/// Returns hex string with `0x` prefix.
pub fn encode_uint256_arg(selector: &[u8; 4], value: u64) -> String {
    format!("0x{}{}", hex::encode(selector), encode_uint256(value))
}

// ── Receipt parsing ──────────────────────────────────────────────

/// Extract the instance address from an `InstanceCreated` event log.
///
/// The event signature is `InstanceCreated(address indexed, address indexed, string, uint256)`.
/// The instance address is in topic 1 (first indexed param).
pub fn parse_instance_address_from_log(topics: &[String]) -> Option<String> {
    if topics.len() < 2 {
        return None;
    }
    let topic0 = topics[0].strip_prefix("0x").unwrap_or(&topics[0]);
    if topic0 != crate::selectors::INSTANCE_CREATED_TOPIC {
        return None;
    }
    Some(decode_address(&topics[1]))
}

#[cfg(test)]
mod abi_tests {
    use super::*;

    #[test]
    fn encode_uint256_zero() {
        let result = encode_uint256(0);
        assert_eq!(result.len(), 64);
        assert_eq!(result, "0".repeat(64));
    }

    #[test]
    fn encode_uint256_one() {
        let result = encode_uint256(1);
        assert!(result.ends_with("1"));
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn encode_string_empty() {
        let result = encode_string("");
        // length = 0 + one padded zero word
        assert_eq!(result.len(), 128); // 64 (length) + 64 (padding)
        assert!(result.starts_with(&"0".repeat(64)));
    }

    #[test]
    fn encode_string_hello() {
        let result = encode_string("hello");
        // length = 5
        assert!(result.starts_with(&format!("{:064x}", 5)));
        // "hello" = 68656c6c6f, padded to 64 hex chars
        let data_part = &result[64..];
        assert!(data_part.starts_with("68656c6c6f"));
        assert_eq!(data_part.len(), 64);
    }

    #[test]
    fn encode_address_with_prefix() {
        let result = encode_address("0x549049a68a0c006790f9671fc11bc8a37067f7c9");
        assert_eq!(result.len(), 64);
        assert!(result.ends_with("549049a68a0c006790f9671fc11bc8a37067f7c9"));
    }

    #[test]
    fn decode_uint256_hex() {
        assert_eq!(decode_uint256(&("0".repeat(63) + "a")).unwrap(), 10);
    }

    #[test]
    fn decode_address_padded() {
        let padded = format!("{:0>64}", "549049a68a0c006790f9671fc11bc8a37067f7c9");
        let addr = decode_address(&padded);
        assert_eq!(addr, "0x549049a68a0c006790f9671fc11bc8a37067f7c9");
    }

    #[test]
    fn encode_execute_step_completed() {
        let calldata = encode_execute_step(1, "");
        assert!(calldata.starts_with("0xf16e3a23"));
    }

    #[test]
    fn encode_create_instance_basic() {
        let names = vec!["Step 1".to_string(), "Step 2".to_string()];
        let types = vec!["approval".to_string(), "approval".to_string()];
        let calldata = encode_create_instance("abc123i0", &names, &types).unwrap();
        assert!(calldata.starts_with("0x6f794b70"));
        // Should contain the template ID somewhere in the data
        let hex_abc = hex::encode("abc123i0");
        assert!(calldata.contains(&hex_abc));
    }

    #[test]
    fn encode_no_args_total_steps() {
        let calldata = encode_no_args(&crate::selectors::TOTAL_STEPS);
        assert_eq!(calldata, "0x6931b3ae");
    }

    #[test]
    fn parse_instance_address_from_creation_log() {
        let topics = vec![
            format!("0x{}", crate::selectors::INSTANCE_CREATED_TOPIC),
            format!("0x{:0>64}", "549049a68a0c006790f9671fc11bc8a37067f7c9"),
            format!("0x{:0>64}", "8cf6fe5cd0905b6bfb81643b0dcda64af32fd762"),
        ];
        let addr = parse_instance_address_from_log(&topics).unwrap();
        assert_eq!(addr, "0x549049a68a0c006790f9671fc11bc8a37067f7c9");
    }

    #[test]
    fn parse_instance_address_wrong_topic() {
        let topics = vec!["0xdeadbeef".to_string()];
        assert!(parse_instance_address_from_log(&topics).is_none());
    }
}
