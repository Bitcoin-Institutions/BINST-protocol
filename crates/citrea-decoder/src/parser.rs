//! Parse Citrea inscriptions from raw Bitcoin tapscript bytes.
//!
//! The tapscript is the second-to-last element of the witness stack
//! in a taproot script-path spend (P2TR).

use crate::types::{ParsedInscription, TransactionKind};

/// Errors that can occur during tapscript parsing.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("script too short ({0} bytes)")]
    TooShort(usize),
    #[error("expected OP_CHECKSIGVERIFY (0xad) at position {0}, got 0x{1:02x}")]
    ExpectedChecksigVerify(usize, u8),
    #[error("unknown transaction kind: 0x{0:04x}")]
    UnknownKind(u16),
    #[error("expected OP_FALSE (0x00) at position {0}, got 0x{1:02x}")]
    ExpectedOpFalse(usize, u8),
    #[error("expected OP_IF (0x63) at position {0}, got 0x{1:02x}")]
    ExpectedOpIf(usize, u8),
    #[error("expected OP_ENDIF (0x68) at position {0}, got 0x{1:02x}")]
    ExpectedOpEndif(usize, u8),
    #[error("expected OP_NIP (0x77) at position {0}, got 0x{1:02x}")]
    ExpectedOpNip(usize, u8),
    #[error("unexpected end of script at position {0}")]
    UnexpectedEnd(usize),
    #[error("pushdata length exceeds remaining script at position {0}")]
    PushdataOverflow(usize),
}

// Bitcoin opcodes we need
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_FALSE: u8 = 0x00; // OP_PUSHBYTES_0
const OP_IF: u8 = 0x63;
const OP_ENDIF: u8 = 0x68;
const OP_NIP: u8 = 0x77;

/// Read a pushdata from the script at `pos`, advancing `pos` past the data.
///
/// Handles OP_PUSHBYTES_1..OP_PUSHBYTES_75, OP_PUSHDATA1, OP_PUSHDATA2.
fn read_pushdata(script: &[u8], pos: &mut usize) -> Result<Vec<u8>, ParseError> {
    if *pos >= script.len() {
        return Err(ParseError::UnexpectedEnd(*pos));
    }

    let opcode = script[*pos];
    *pos += 1;

    let len = if opcode <= 75 {
        // OP_PUSHBYTES_N: next N bytes are data
        opcode as usize
    } else if opcode == 0x4c {
        // OP_PUSHDATA1: next 1 byte is length
        if *pos >= script.len() {
            return Err(ParseError::UnexpectedEnd(*pos));
        }
        let l = script[*pos] as usize;
        *pos += 1;
        l
    } else if opcode == 0x4d {
        // OP_PUSHDATA2: next 2 bytes are length (LE)
        if *pos + 1 >= script.len() {
            return Err(ParseError::UnexpectedEnd(*pos));
        }
        let l = u16::from_le_bytes([script[*pos], script[*pos + 1]]) as usize;
        *pos += 2;
        l
    } else {
        // Unexpected opcode where we expected pushdata
        return Err(ParseError::UnexpectedEnd(*pos - 1));
    };

    if *pos + len > script.len() {
        return Err(ParseError::PushdataOverflow(*pos));
    }

    let data = script[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(data)
}

/// Expect a specific opcode at `pos`, advancing past it.
fn expect_opcode(script: &[u8], pos: &mut usize, expected: u8) -> Result<(), ParseError> {
    if *pos >= script.len() {
        return Err(ParseError::UnexpectedEnd(*pos));
    }
    let got = script[*pos];
    *pos += 1;
    if got != expected {
        let err = match expected {
            OP_CHECKSIGVERIFY => ParseError::ExpectedChecksigVerify(*pos - 1, got),
            OP_FALSE => ParseError::ExpectedOpFalse(*pos - 1, got),
            OP_IF => ParseError::ExpectedOpIf(*pos - 1, got),
            OP_ENDIF => ParseError::ExpectedOpEndif(*pos - 1, got),
            OP_NIP => ParseError::ExpectedOpNip(*pos - 1, got),
            _ => ParseError::UnexpectedEnd(*pos - 1),
        };
        return Err(err);
    }
    Ok(())
}

/// Parse a Citrea inscription from raw tapscript bytes.
///
/// The tapscript is the second-to-last witness element in a P2TR
/// script-path spend. The last element is the control block.
///
/// # Format
///
/// ```text
/// PUSH32 <x_only_pubkey>
/// OP_CHECKSIGVERIFY
/// PUSH2 <kind_bytes_le>
/// OP_FALSE OP_IF
///   PUSH <signature>
///   PUSH <signer_pubkey>
///   PUSH <body_chunk>...     (concatenated for multi-chunk bodies)
/// OP_ENDIF
/// PUSH8 <nonce_le>
/// OP_NIP
/// ```
pub fn parse_tapscript(script: &[u8]) -> Result<ParsedInscription, ParseError> {
    if script.len() < 40 {
        return Err(ParseError::TooShort(script.len()));
    }

    let mut pos = 0;

    // 1. Read x-only public key (PUSH32 + 32 bytes)
    let pubkey_data = read_pushdata(script, &mut pos)?;
    if pubkey_data.len() != 32 {
        return Err(ParseError::TooShort(pubkey_data.len()));
    }
    let mut tapscript_pubkey = [0u8; 32];
    tapscript_pubkey.copy_from_slice(&pubkey_data);

    // 2. OP_CHECKSIGVERIFY
    expect_opcode(script, &mut pos, OP_CHECKSIGVERIFY)?;

    // 3. Read kind (PUSH2 + 2 bytes LE)
    let kind_data = read_pushdata(script, &mut pos)?;
    if kind_data.len() != 2 {
        return Err(ParseError::TooShort(kind_data.len()));
    }
    let kind_u16 = u16::from_le_bytes([kind_data[0], kind_data[1]]);
    let kind = TransactionKind::from_le_bytes([kind_data[0], kind_data[1]])
        .ok_or(ParseError::UnknownKind(kind_u16))?;

    // 4. OP_FALSE OP_IF  (start of inscription envelope)
    expect_opcode(script, &mut pos, OP_FALSE)?;
    expect_opcode(script, &mut pos, OP_IF)?;

    // 5. Read signature
    let signature = read_pushdata(script, &mut pos)?;

    // 6. Read signer public key
    let signer_pubkey = read_pushdata(script, &mut pos)?;

    // 7. Read body chunks until OP_ENDIF
    //    For SequencerCommitment there's usually just one chunk.
    //    For Complete/Aggregate proofs, body is split into ≤520-byte chunks.
    let mut body = Vec::new();
    loop {
        if pos >= script.len() {
            return Err(ParseError::UnexpectedEnd(pos));
        }
        if script[pos] == OP_ENDIF {
            pos += 1;
            break;
        }
        let chunk = read_pushdata(script, &mut pos)?;
        body.extend_from_slice(&chunk);
    }

    // 8. Read nonce (PUSH8 + 8 bytes LE)
    let nonce_data = read_pushdata(script, &mut pos)?;
    let nonce = if nonce_data.len() == 8 {
        i64::from_le_bytes(nonce_data.try_into().unwrap())
    } else {
        // Variable-length nonce — pad or interpret as-is
        let mut buf = [0u8; 8];
        let len = nonce_data.len().min(8);
        buf[..len].copy_from_slice(&nonce_data[..len]);
        i64::from_le_bytes(buf)
    };

    // 9. OP_NIP
    expect_opcode(script, &mut pos, OP_NIP)?;

    Ok(ParsedInscription {
        tapscript_pubkey,
        kind,
        signature,
        signer_pubkey,
        body,
        nonce,
    })
}

/// Check whether a wtxid (as raw bytes) starts with the Citrea reveal prefix.
pub fn has_citrea_prefix(wtxid: &[u8], prefix: &[u8]) -> bool {
    wtxid.starts_with(prefix)
}

/// Extract the tapscript from a witness stack.
///
/// In a P2TR script-path spend, the witness is:
///   `[<script_args>..., <tapscript>, <control_block>]`
///
/// The tapscript is the second-to-last element.
pub fn extract_tapscript(witness: &[Vec<u8>]) -> Option<&[u8]> {
    if witness.len() >= 2 {
        Some(&witness[witness.len() - 2])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TransactionKind;

    /// Real tapscript from block 127600, tx[136] on Bitcoin testnet4.
    /// This is a Citrea SequencerCommitment (#16649, L2 end block 23924028).
    /// Extracted from txid 4635dc1a1ab3ec28b7967ad68fd5bde1cd05461dfcb8cc090642ba1d7b6826a7
    const REAL_TAPSCRIPT_HEX: &str = "\
        20\
        015a7c4d2cc1c771198686e2ebef6fe7004f4136d61f6225b061d1bb9b821b9b\
        ad\
        02\
        0400\
        00\
        63\
        40\
        c46f177f783ee2c6758642452d0750c4303233dc370db34feb35e2d4d35119aa\
        5ec7188e127c3d0b22e3ab4df3e29b5040d4c92833d826d80468f8d7a059f696\
        21\
        03015a7c4d2cc1c771198686e2ebef6fe7004f4136d61f6225b061d1bb9b821b9b\
        2d\
        04\
        af4f719392919602d1cbdd5e9b5657aba885b34ba73bb4597a25c4c61f6f94bc\
        09410000\
        3c0d6d0100000000\
        68\
        08\
        1000000000000000\
        77\
    ";

    #[test]
    fn parse_real_sequencer_commitment() {
        let script = hex::decode(REAL_TAPSCRIPT_HEX).expect("valid hex");
        let parsed = parse_tapscript(&script).expect("should parse");

        assert_eq!(parsed.kind, TransactionKind::SequencerCommitment);
        assert_eq!(parsed.signature.len(), 64);
        assert_eq!(parsed.signer_pubkey.len(), 33);

        let sc = parsed.as_sequencer_commitment().expect("should be SeqCommit");
        assert_eq!(sc.index, 16649);
        assert_eq!(sc.l2_end_block_number, 23924028);
        assert_eq!(parsed.nonce, 16);
    }

    #[test]
    fn reject_too_short() {
        let result = parse_tapscript(&[0x00; 10]);
        assert!(result.is_err());
    }
}
