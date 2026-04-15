//! Pure-Rust Bitcoin inscription pipeline for BINST.
//!
//! This crate provides:
//! - **PSBT construction** for commit+reveal inscription pairs
//! - **Inscription script builder** with Ordinals envelope format
//! - **UTXO management** (fetch, filter, coin selection)
//! - **Broadcast** via Mempool.space API or Bitcoin Core RPC
//! - **Confirmation polling** for inscription tracking
//!
//! ## Feature flags
//!
//! - `std` (default) — synchronous HTTP via `ureq`, for CLI usage
//! - `wasm` — browser `fetch` via `web-sys`, for webapp usage
//!
//! ## Architecture
//!
//! The core PSBT/script building is pure, no-IO, and works everywhere.
//! The HTTP transport layer (UTXO fetch, broadcast, poll) is feature-gated.
//!
//! Ported from `webapp/binst-pilot-webapp/src/txbuilder.rs` and
//! `webapp/binst-pilot-webapp/src/inscribe.rs`.

pub mod script;
pub mod txbuilder;
pub mod types;

#[cfg(feature = "std")]
pub mod mempool;

#[cfg(test)]
mod tests;
