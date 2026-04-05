//! Ordinals envelope parser — extracts inscription fields from tapscript witness data.
//!
//! An Ordinals inscription lives inside a tapscript witness item as:
//!
//! ```text
//! OP_FALSE OP_IF
//!   OP_PUSH "ord"                    ← magic marker
//!   <tag> <value> <tag> <value> ...  ← tagged fields
//!   OP_0                             ← body separator
//!   <body_chunk> <body_chunk> ...    ← body data
//! OP_ENDIF
//! ```
//!
//! Tags (from Ordinals spec):
//!   1 = content type
//!   2 = pointer
//!   3 = parent
//!   5 = metadata (CBOR)
//!   7 = metaprotocol
//!   9 = encoding
//!  11 = delegate

use crate::types::{parse_binst_body, BinstEntity};

/// A parsed Ordinals inscription envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrdEnvelope {
    /// Content type (tag 1), e.g. "application/json".
    pub content_type: Option<String>,

    /// Metaprotocol (tag 7), e.g. "binst".
    pub metaprotocol: Option<String>,

    /// Parent inscription ID (tag 3), raw bytes.
    pub parent: Option<Vec<u8>>,

    /// Pointer (tag 2), raw bytes.
    pub pointer: Option<Vec<u8>>,

    /// Metadata (tag 5), raw CBOR bytes.
    pub metadata: Option<Vec<u8>>,

    /// Concatenated body data.
    pub body: Vec<u8>,
}

impl OrdEnvelope {
    /// Whether this is a BINST inscription (metaprotocol = "binst").
    pub fn is_binst(&self) -> bool {
        self.metaprotocol.as_deref() == Some("binst")
    }

    /// Try to parse the body as a BINST entity (JSON).
    pub fn parse_binst(&self) -> Option<Result<BinstEntity, serde_json::Error>> {
        if !self.is_binst() {
            return None;
        }
        let json = std::str::from_utf8(&self.body).ok()?;
        Some(parse_binst_body(json))
    }
}

// ── Script opcodes ───────────────────────────────────────────────

const OP_FALSE: u8 = 0x00;
const OP_IF: u8 = 0x63;
const OP_ENDIF: u8 = 0x68;
const OP_0: u8 = 0x00; // same as OP_FALSE, used as body separator
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;

// Ordinals tag numbers
const TAG_CONTENT_TYPE: u8 = 1;
const TAG_POINTER: u8 = 2;
const TAG_PARENT: u8 = 3;
const TAG_METADATA: u8 = 5;
const TAG_METAPROTOCOL: u8 = 7;

/// Extract all Ordinals envelopes from a tapscript witness item.
///
/// A single witness item can contain multiple inscriptions.
/// Returns an empty vec if no envelopes are found.
pub fn extract_envelopes(script: &[u8]) -> Vec<OrdEnvelope> {
    let mut envelopes = Vec::new();
    let mut pos = 0;

    while pos < script.len() {
        // Scan for OP_FALSE OP_IF
        if let Some(envelope_start) = find_envelope_start(script, pos) {
            pos = envelope_start;
            match parse_envelope(script, &mut pos) {
                Some(env) => envelopes.push(env),
                None => pos += 1, // malformed, skip and keep scanning
            }
        } else {
            break;
        }
    }

    envelopes
}

/// Find the next `OP_FALSE OP_IF` sequence starting from `from`.
fn find_envelope_start(script: &[u8], from: usize) -> Option<usize> {
    if script.len() < 2 {
        return None;
    }
    for i in from..script.len() - 1 {
        if script[i] == OP_FALSE && script[i + 1] == OP_IF {
            return Some(i);
        }
    }
    None
}

/// Parse a single envelope starting at the OP_FALSE position.
/// Advances `pos` past OP_ENDIF on success.
fn parse_envelope(script: &[u8], pos: &mut usize) -> Option<OrdEnvelope> {
    // Skip OP_FALSE OP_IF
    *pos += 2;

    // Expect "ord" magic push
    let ord_push = read_push(script, pos)?;
    if ord_push != b"ord" {
        return None;
    }

    let mut content_type = None;
    let mut metaprotocol = None;
    let mut parent = None;
    let mut pointer = None;
    let mut metadata = None;
    let mut body = Vec::new();
    let mut in_body = false;

    loop {
        if *pos >= script.len() {
            return None; // unexpected end
        }

        let opcode = script[*pos];

        if opcode == OP_ENDIF {
            *pos += 1;
            break;
        }

        if !in_body && opcode == OP_0 {
            // Body separator — but only if this is a bare OP_0, not a push
            // In Ordinals, OP_0 (0x00) as a tag separator means "start body"
            in_body = true;
            *pos += 1;
            continue;
        }

        if in_body {
            // Read body chunks
            if let Some(chunk) = read_push(script, pos) {
                body.extend_from_slice(&chunk);
            } else {
                // Not a push opcode — probably OP_ENDIF handled above
                break;
            }
        } else {
            // Read tag-value pairs
            let tag_push = read_push(script, pos)?;
            if tag_push.len() != 1 {
                // Multi-byte or empty tag — skip the value too
                let _value = read_push(script, pos)?;
                continue;
            }
            let tag = tag_push[0];
            let value = read_push(script, pos)?;

            match tag {
                TAG_CONTENT_TYPE => {
                    content_type = String::from_utf8(value).ok();
                }
                TAG_METAPROTOCOL => {
                    metaprotocol = String::from_utf8(value).ok();
                }
                TAG_PARENT => {
                    parent = Some(value);
                }
                TAG_POINTER => {
                    pointer = Some(value);
                }
                TAG_METADATA => {
                    metadata = Some(value);
                }
                _ => {
                    // Unknown tag — ignore (forward compatible)
                }
            }
        }
    }

    Some(OrdEnvelope {
        content_type,
        metaprotocol,
        parent,
        pointer,
        metadata,
        body,
    })
}

/// Read a data push from the script. Handles OP_PUSH_N (0x01..0x4b),
/// OP_PUSHDATA1, OP_PUSHDATA2, and OP_PUSHDATA4.
/// Returns None if the opcode is not a push.
fn read_push(script: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    if *pos >= script.len() {
        return None;
    }

    let opcode = script[*pos];

    // Direct push: 0x01..0x4b means push next N bytes
    if (1..=0x4b).contains(&opcode) {
        let len = opcode as usize;
        *pos += 1;
        if *pos + len > script.len() {
            return None;
        }
        let data = script[*pos..*pos + len].to_vec();
        *pos += len;
        return Some(data);
    }

    match opcode {
        OP_PUSHDATA1 => {
            *pos += 1;
            if *pos >= script.len() {
                return None;
            }
            let len = script[*pos] as usize;
            *pos += 1;
            if *pos + len > script.len() {
                return None;
            }
            let data = script[*pos..*pos + len].to_vec();
            *pos += len;
            Some(data)
        }
        OP_PUSHDATA2 => {
            *pos += 1;
            if *pos + 2 > script.len() {
                return None;
            }
            let len = u16::from_le_bytes([script[*pos], script[*pos + 1]]) as usize;
            *pos += 2;
            if *pos + len > script.len() {
                return None;
            }
            let data = script[*pos..*pos + len].to_vec();
            *pos += len;
            Some(data)
        }
        OP_PUSHDATA4 => {
            *pos += 1;
            if *pos + 4 > script.len() {
                return None;
            }
            let len = u32::from_le_bytes([
                script[*pos],
                script[*pos + 1],
                script[*pos + 2],
                script[*pos + 3],
            ]) as usize;
            *pos += 4;
            if *pos + len > script.len() {
                return None;
            }
            let data = script[*pos..*pos + len].to_vec();
            *pos += len;
            Some(data)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Ordinals envelope script.
    fn build_envelope(content_type: &str, metaprotocol: &str, body: &[u8]) -> Vec<u8> {
        let mut script = Vec::new();

        // OP_FALSE OP_IF
        script.push(OP_FALSE);
        script.push(OP_IF);

        // Push "ord"
        script.push(3); // push 3 bytes
        script.extend_from_slice(b"ord");

        // Tag 1 (content type)
        script.push(1); // push 1 byte
        script.push(TAG_CONTENT_TYPE);
        push_data(&mut script, content_type.as_bytes());

        // Tag 7 (metaprotocol)
        script.push(1);
        script.push(TAG_METAPROTOCOL);
        push_data(&mut script, metaprotocol.as_bytes());

        // OP_0 (body separator)
        script.push(OP_0);

        // Body
        push_data(&mut script, body);

        // OP_ENDIF
        script.push(OP_ENDIF);

        script
    }

    fn push_data(script: &mut Vec<u8>, data: &[u8]) {
        let len = data.len();
        if len <= 0x4b {
            script.push(len as u8);
            script.extend_from_slice(data);
        } else if len <= 0xff {
            script.push(OP_PUSHDATA1);
            script.push(len as u8);
            script.extend_from_slice(data);
        } else {
            script.push(OP_PUSHDATA2);
            script.extend_from_slice(&(len as u16).to_le_bytes());
            script.extend_from_slice(data);
        }
    }

    #[test]
    fn extract_binst_inscription() {
        let body = br#"{"v":0,"type":"institution","name":"Test","admin":"aaaa000000000000000000000000000000000000000000000000000000000000"}"#;
        let script = build_envelope("application/json", "binst", body);

        let envelopes = extract_envelopes(&script);
        assert_eq!(envelopes.len(), 1);

        let env = &envelopes[0];
        assert_eq!(env.content_type.as_deref(), Some("application/json"));
        assert_eq!(env.metaprotocol.as_deref(), Some("binst"));
        assert!(env.is_binst());
        assert_eq!(env.body, body);

        // Parse the BINST body
        let entity = env.parse_binst().unwrap().unwrap();
        match entity {
            BinstEntity::Institution(inst) => {
                assert_eq!(inst.name, "Test");
            }
            _ => panic!("Expected Institution"),
        }
    }

    #[test]
    fn ignore_non_binst_inscription() {
        let script = build_envelope("image/png", "brc-20", b"not binst");

        let envelopes = extract_envelopes(&script);
        assert_eq!(envelopes.len(), 1);
        assert!(!envelopes[0].is_binst());
        assert!(envelopes[0].parse_binst().is_none());
    }

    #[test]
    fn extract_with_parent_tag() {
        let mut script = Vec::new();

        // OP_FALSE OP_IF
        script.push(OP_FALSE);
        script.push(OP_IF);

        // "ord"
        script.push(3);
        script.extend_from_slice(b"ord");

        // content type
        script.push(1);
        script.push(TAG_CONTENT_TYPE);
        push_data(&mut script, b"application/json");

        // metaprotocol
        script.push(1);
        script.push(TAG_METAPROTOCOL);
        push_data(&mut script, b"binst");

        // parent (tag 3) — 36-byte fake inscription ID
        script.push(1);
        script.push(TAG_PARENT);
        let fake_parent = [0xab; 36];
        push_data(&mut script, &fake_parent);

        // body separator
        script.push(OP_0);

        // body
        let body = br#"{"v":0,"type":"process_template","name":"KYC","steps":[{"name":"Upload"}]}"#;
        push_data(&mut script, body);

        script.push(OP_ENDIF);

        let envelopes = extract_envelopes(&script);
        assert_eq!(envelopes.len(), 1);
        assert!(envelopes[0].is_binst());
        assert_eq!(envelopes[0].parent.as_deref(), Some(&fake_parent[..]));
    }

    #[test]
    fn no_envelope_in_random_data() {
        let script = vec![0x51, 0x52, 0x93, 0x87]; // OP_1 OP_2 OP_ADD OP_EQUAL
        let envelopes = extract_envelopes(&script);
        assert!(envelopes.is_empty());
    }

    #[test]
    fn handle_pushdata1() {
        // Build a body longer than 0x4b bytes to force PUSHDATA1
        let long_body = br#"{"v":0,"type":"institution","name":"A Very Long Institution Name That Exceeds Normal Push","admin":"bbbb000000000000000000000000000000000000000000000000000000000000"}"#;
        assert!(long_body.len() > 0x4b);

        let script = build_envelope("application/json", "binst", long_body);
        let envelopes = extract_envelopes(&script);
        assert_eq!(envelopes.len(), 1);
        assert!(envelopes[0].is_binst());
        assert_eq!(envelopes[0].body, long_body.to_vec());
    }
}
