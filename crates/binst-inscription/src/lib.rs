//! # binst-inscription
//!
//! Parse `binst` metaprotocol Ordinals inscriptions from Bitcoin witness data.
//!
//! This crate extracts Ordinals envelope fields from taproot witness scripts
//! and deserializes the JSON body into typed BINST entities. It recognises
//! inscriptions with `metaprotocol = "binst"` and `content_type = "application/json"`.
//!
//! ## Architecture
//!
//! ```text
//! Bitcoin witness item (tapscript)
//!   → extract_envelope()        — find OP_FALSE OP_IF ... OP_ENDIF, parse tags
//!     → OrdEnvelope { content_type, metaprotocol, parent, body, ... }
//!       → parse_binst_body()    — deserialize JSON body into BinstEntity
//!         → Institution | ProcessTemplate | ProcessInstance | StepExecution
//! ```

pub mod envelope;
pub mod types;

pub use envelope::*;
pub use types::*;
