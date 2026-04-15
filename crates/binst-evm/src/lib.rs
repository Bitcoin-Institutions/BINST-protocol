//! Pure-Rust EVM ABI encoding and JSON-RPC client for BINST smart contracts.
//!
//! This crate provides:
//! - **ABI encoding/decoding** for `BINSTProcessFactory` and `BINSTProcess` contracts
//! - **JSON-RPC client** for `eth_call`, `eth_sendRawTransaction`, `eth_getTransactionReceipt`
//! - **Finality queries** for `citrea_getLastCommittedL2Height` / `citrea_getLastProvenL2Height`
//! - **Contract bytecode** constants for deployment (from compiled Hardhat artifacts)
//!
//! ## Feature flags
//!
//! - `std` (default) — synchronous HTTP via `ureq`, for CLI usage
//! - `wasm` — browser `fetch` via `web-sys`, for webapp usage
//!
//! ## Architecture
//!
//! This crate is **transport-agnostic** at its core. The ABI encoding functions
//! are pure, no-IO, and work in both `std` and `wasm` contexts. The JSON-RPC
//! layer is gated behind feature flags.

pub mod abi;
pub mod selectors;
pub mod types;

#[cfg(feature = "std")]
pub mod rpc;

#[cfg(test)]
mod tests;
