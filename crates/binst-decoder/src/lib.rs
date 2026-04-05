//! # binst-decoder
//!
//! Map L2 DA state diffs to BINST protocol entities.
//!
//! This crate sits above `citrea-decoder` and adds BINST-specific knowledge:
//!
//! - **Storage layout** — deterministic slot formulas for `Institution.sol`,
//!   `ProcessTemplate.sol`, `ProcessInstance.sol`, and `BINSTDeployer.sol`.
//!
//! - **Entity types** — `InstitutionState`, `ProcessTemplateState`,
//!   `ProcessInstanceState`, each carrying an optional `BitcoinIdentity`
//!   where the Bitcoin pubkey is the root of authority and the L2 EVM
//!   address is a processing delegate.
//!
//! - **State reconstruction** — given a stream of `(contract, slot, value)`
//!   tuples extracted from batch-proof state diffs, reconstruct the full
//!   protocol state: institution names, members, process progress, etc.
//!
//! - **Value decoding** — the [`value`] module decodes raw Citrea storage
//!   values (which are in little-endian word order) into human-readable
//!   form: addresses, integers, booleans, short Solidity strings, and
//!   packed `StepState` structs.
//!
//! ## Architecture
//!
//! ```text
//! Bitcoin block
//!   → citrea-decoder  (find Citrea inscriptions, decode Borsh)
//!     → batch proof body  (contains compressed state diff)
//!       → binst-decoder  (map storage slots → protocol entities)
//!         → InstitutionState, ProcessTemplateState, ProcessInstanceState
//!         → value::DecodedValue (human-readable decoded values)
//! ```

pub mod diff;
pub mod entities;
pub mod jmt;
pub mod storage;
pub mod value;
pub mod vault;

pub use entities::*;
pub use storage::*;
