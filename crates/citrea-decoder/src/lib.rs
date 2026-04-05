//! # citrea-decoder
//!
//! Decode Citrea Data Availability inscriptions from Bitcoin taproot witness data.
//!
//! Citrea inscribes sequencer commitments, batch proofs, and other DA artifacts
//! into Bitcoin using a taproot commit-reveal pattern. This crate parses the
//! reveal transaction's tapscript and Borsh-deserializes the embedded data.
//!
//! ## Tapscript format
//!
//! ```text
//! <x_only_pubkey>           32 bytes
//! OP_CHECKSIGVERIFY
//! <kind_bytes>              2 bytes LE (0=Complete, 1=Aggregate, 2=Chunk, 3=MethodId, 4=SeqCommit)
//! OP_FALSE
//! OP_IF
//!   <signature>             64 bytes
//!   <signer_pubkey>         33 bytes (compressed)
//!   <body_chunk>...         up to 520 bytes each, concatenated
//! OP_ENDIF
//! <nonce>                   8 bytes LE
//! OP_NIP
//! ```
//!
//! The body is `borsh(DataOnDa::Variant(payload))`.
//! For SequencerCommitment the payload is `{ merkle_root: [u8;32], index: u32, l2_end_block_number: u64 }`.

mod types;
mod parser;
pub mod proof;

pub use types::*;
pub use parser::*;
