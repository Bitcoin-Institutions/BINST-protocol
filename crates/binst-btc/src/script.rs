//! Inscription script builder — Ordinals envelope format.
//!
//! Ported from `webapp/binst-pilot-webapp/src/txbuilder.rs` (lines 91–155).

use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::Builder as ScriptBuilder;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::opcodes;
use bitcoin::opcodes::OP_0;
use bitcoin::ScriptBuf;

use binst_inscription::BinstEntity;

/// Maximum single pushdata in Tapscript (520 bytes).
const MAX_PUSH: usize = 520;

/// Build the Tapscript inscription envelope for a BINST entity.
///
/// Layout (Ordinals standard):
/// ```text
/// <admin_pubkey> OP_CHECKSIG
/// OP_FALSE OP_IF
///   OP_PUSH "ord"
///   OP_PUSH 3  OP_PUSH <parent_txid_bytes>   ← only when parent is set
///   OP_PUSH 1  OP_PUSH <content_type>
///   OP_PUSH 7  OP_PUSH "binst"
///   OP_0
///   OP_PUSH <body_chunk_1>
///   OP_PUSH <body_chunk_2>
///   ...
/// OP_ENDIF
/// ```
///
/// `parent_inscription_id` — optional Ordinals inscription ID of the parent
/// entity. Format: `<txid>i<vout>`. The txid bytes are reversed (LE) before
/// being pushed, per the Ordinals spec.
pub fn build_inscription_script(
    entity: &BinstEntity,
    admin_pubkey: &XOnlyPublicKey,
    parent_inscription_id: Option<&str>,
) -> Result<ScriptBuf, String> {
    let body = serde_json::to_vec(entity).map_err(|e| format!("JSON serialize: {e}"))?;
    let content_type = b"application/json";

    let mut builder = ScriptBuilder::new()
        .push_x_only_key(admin_pubkey)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(opcodes::OP_FALSE)
        .push_opcode(OP_IF);

    builder = push_bytes_checked(builder, b"ord")?;

    // Parent tag (tag 3) — optional
    if let Some(parent_id) = parent_inscription_id {
        let parent_bytes = encode_parent_id_bytes(parent_id)?;
        builder = builder.push_int(3);
        builder = push_bytes_checked(builder, &parent_bytes)?;
    }

    // Content type (tag 1)
    builder = builder.push_int(1);
    builder = push_bytes_checked(builder, content_type)?;

    // Metaprotocol (tag 7)
    builder = builder.push_int(7);
    builder = push_bytes_checked(builder, b"binst")?;

    // Body (tag 0) — chunked to ≤520 bytes
    builder = builder.push_opcode(OP_0);
    for chunk in body.chunks(MAX_PUSH) {
        builder = push_bytes_checked(builder, chunk)?;
    }

    builder = builder.push_opcode(OP_ENDIF);

    Ok(builder.into_script())
}

/// Push bytes into a script builder, choosing the right pushdata encoding.
fn push_bytes_checked(
    builder: ScriptBuilder,
    data: &[u8],
) -> Result<ScriptBuilder, String> {
    let push = bitcoin::script::PushBytesBuf::try_from(data.to_vec())
        .map_err(|e| format!("push_bytes: {e}"))?;
    Ok(builder.push_slice(push))
}

/// Encode an Ordinals parent inscription ID to the wire format.
///
/// Format: `<txid_le_bytes><vout_le_bytes>` where vout is only included
/// if non-zero, and uses minimal-length encoding.
fn encode_parent_id_bytes(parent_id: &str) -> Result<Vec<u8>, String> {
    let parts: Vec<&str> = parent_id.split('i').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid parent ID format: {parent_id}"));
    }
    let txid_hex = parts[0];
    let vout: u32 = parts[1]
        .parse()
        .map_err(|e| format!("Invalid vout in parent ID: {e}"))?;

    // Decode txid and reverse to little-endian
    let txid_bytes = hex::decode(txid_hex)
        .map_err(|e| format!("Invalid txid hex: {e}"))?;
    if txid_bytes.len() != 32 {
        return Err(format!("txid must be 32 bytes, got {}", txid_bytes.len()));
    }
    let mut le_txid = txid_bytes;
    le_txid.reverse();

    // Append vout as minimal LE bytes (omit trailing zeros, but always at least 0 bytes for vout 0)
    if vout == 0 {
        // Vout 0 is implicit — don't append anything
        Ok(le_txid)
    } else {
        let vout_bytes = vout.to_le_bytes();
        // Trim trailing zeros for minimal encoding
        let mut len = 4;
        while len > 1 && vout_bytes[len - 1] == 0 {
            len -= 1;
        }
        le_txid.extend_from_slice(&vout_bytes[..len]);
        Ok(le_txid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_parent_id_vout_zero() {
        let result = encode_parent_id_bytes(
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2i0",
        )
        .unwrap();
        // 32 bytes txid (reversed), no vout bytes
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn encode_parent_id_vout_one() {
        let result = encode_parent_id_bytes(
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2i1",
        )
        .unwrap();
        // 32 bytes txid + 1 byte vout
        assert_eq!(result.len(), 33);
        assert_eq!(result[32], 1);
    }

    #[test]
    fn encode_parent_id_invalid() {
        assert!(encode_parent_id_bytes("not-a-valid-id").is_err());
    }
}
