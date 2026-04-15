//! # Miniscript Vault Policies for BINST
//!
//! Compile institutional spending policies into Taproot descriptors using
//! [BIP 379](https://github.com/bitcoin/bips/blob/master/bip-0379.md)
//! miniscript.
//!
//! The standard BINST vault has **two** spending paths:
//!
//! 1. **Admin (CSV-delayed)** — `and(pk(admin), older(csv_delay))`
//!    Safe transfer after a relative time-lock (~1 day at default).
//! 2. **Committee (immediate)** — `thresh(2, pk(A), pk(B), pk(C))`
//!    Emergency 2-of-3 recovery path, usable at any time.
//!
//! Both live in Taproot script leaves; the internal key is a provably
//! unspendable NUMS point so funds can *only* be spent via script-path.
//!
//! ## Vault vs. inscription sat — discoverability
//!
//! The vault address is written into the institution's inscription JSON body
//! (`"vault": "tb1p…"`) as a protocol-layer custody declaration.  The
//! inscription sat itself always stays at the wallet's plain P2TR address
//! (`change_address`) so Ordinals indexers can discover it by wallet address.
//!
//! Parent-UTXO chaining (child reveal spends parent sat as input 1) works
//! because the parent sat lives at the wallet's key-path address, which the
//! wallet can sign immediately without any CSV delay.  The vault is for
//! *operational value*, not for the inscription sat.

use std::fmt;
use std::str::FromStr;
use std::string::String;
use std::vec;
use std::vec::Vec;

use miniscript::bitcoin::secp256k1::XOnlyPublicKey;
use miniscript::bitcoin::Network;
use miniscript::policy::concrete::Policy as Concrete;
use miniscript::Descriptor;

/// Provably unspendable x-only key (Ordinals NUMS point).
/// No known discrete logarithm — identical to `taproot-vault.ts`.
pub const NUMS_KEY_HEX: &str =
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/// Default CSV delay in blocks (~1 day at 10 min/block).
pub const DEFAULT_CSV_DELAY: u16 = 144;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Input parameters for a BINST vault.
#[derive(Debug, Clone)]
pub struct VaultPolicy {
    /// Admin pubkey — can spend after CSV delay.
    pub admin: XOnlyPublicKey,
    /// Committee pubkeys — 2-of-3 immediate spend.
    pub committee: [XOnlyPublicKey; 3],
    /// CSV delay in blocks (default: 144).
    pub csv_delay: u16,
}

/// Compiled Taproot descriptor and derived metadata.
#[derive(Debug, Clone)]
pub struct VaultDescriptor {
    /// Full `tr(NUMS, {…})` descriptor string.
    pub descriptor: String,
    /// Testnet address (`tb1p…`).
    pub address_testnet: String,
    /// Mainnet address (`bc1p…`).
    pub address_mainnet: String,
    /// Human-readable spending paths.
    pub spending_paths: Vec<SpendingPath>,
}

/// A single spending path inside the Taproot tree.
#[derive(Debug, Clone)]
pub struct SpendingPath {
    /// E.g. "Admin (CSV-delayed)" or "Committee (immediate)".
    pub name: String,
    /// Hex pubkeys required to satisfy this path.
    pub required_keys: Vec<String>,
    /// CSV timelock in blocks, if any.
    pub timelock_blocks: Option<u16>,
    /// Worst-case witness size in virtual bytes.
    pub witness_size: usize,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during vault policy compilation.
#[derive(Debug)]
pub enum VaultError {
    /// The NUMS key hex could not be parsed.
    NumsKeyParse(String),
    /// Miniscript policy compilation failed.
    Compile(String),
    /// Address derivation failed.
    Address(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NumsKeyParse(e) => write!(f, "NUMS key parse error: {e}"),
            Self::Compile(e) => write!(f, "policy compilation error: {e}"),
            Self::Address(e) => write!(f, "address derivation error: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl VaultPolicy {
    /// Create a new vault policy with the default CSV delay (144 blocks).
    pub fn new(admin: XOnlyPublicKey, committee: [XOnlyPublicKey; 3]) -> Self {
        Self {
            admin,
            committee,
            csv_delay: DEFAULT_CSV_DELAY,
        }
    }

    /// Compile this policy into a full Taproot descriptor.
    ///
    /// Uses the NUMS internal key so the key-path is unspendable and
    /// all spending goes through script-path leaves.
    pub fn compile(&self) -> Result<VaultDescriptor, VaultError> {
        let nums = XOnlyPublicKey::from_str(NUMS_KEY_HEX)
            .map_err(|e| VaultError::NumsKeyParse(e.to_string()))?;

        // Build the 2-leaf policy string:
        //   or(and(pk(<admin>), older(<csv>)),    ← leaf 0: CSV-delayed transfer
        //      thresh(2, pk(A), pk(B), pk(C)))     ← leaf 1: committee emergency
        //
        // Note: miniscript rejects policies with the same key in multiple leaves
        // ("duplicate keys"), so a third admin-only chaining leaf is not possible
        // here.  Parent-UTXO chaining works via the wallet's plain key-path address
        // (change_address) — no vault leaf needed for that operation.
        let policy_str = format!(
            "or(and(pk({}),older({})),thresh(2,pk({}),pk({}),pk({})))",
            self.admin,
            self.csv_delay,
            self.committee[0],
            self.committee[1],
            self.committee[2],
        );

        let policy = Concrete::<XOnlyPublicKey>::from_str(&policy_str)
            .map_err(|e| VaultError::Compile(e.to_string()))?;

        let descriptor = policy
            .compile_tr(Some(nums))
            .map_err(|e| VaultError::Compile(e.to_string()))?;

        let desc_string = descriptor.to_string();

        let address_testnet = derive_address(&descriptor, Network::Testnet)?;
        let address_mainnet = derive_address(&descriptor, Network::Bitcoin)?;

        let spending_paths = self.analyze();

        Ok(VaultDescriptor {
            descriptor: desc_string,
            address_testnet,
            address_mainnet,
            spending_paths,
        })
    }

    /// Enumerate the spending paths without compiling the full descriptor.
    pub fn analyze(&self) -> Vec<SpendingPath> {
        vec![
            SpendingPath {
                name: String::from("Admin (CSV-delayed)"),
                required_keys: vec![self.admin.to_string()],
                timelock_blocks: Some(self.csv_delay),
                // Control block (33) + schnorr sig (64) + script (~40)
                witness_size: 137,
            },
            SpendingPath {
                name: String::from("Committee (immediate)"),
                required_keys: self.committee.iter().map(|k| k.to_string()).collect(),
                timelock_blocks: None,
                // Control block (33) + 2 schnorr sigs (128) + script (~60)
                witness_size: 170,
            },
        ]
    }
}

impl VaultDescriptor {
    /// Derive the address for a specific network from the descriptor string.
    pub fn address(&self, network: Network) -> &str {
        match network {
            Network::Bitcoin => &self.address_mainnet,
            _ => &self.address_testnet,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn derive_address(
    descriptor: &Descriptor<XOnlyPublicKey>,
    network: Network,
) -> Result<String, VaultError> {
    descriptor
        .address(network)
        .map(|a| a.to_string())
        .map_err(|e| VaultError::Address(e.to_string()))
}

/// Parse an x-only public key from a 64-char hex string.
pub fn parse_xonly(hex: &str) -> Result<XOnlyPublicKey, VaultError> {
    XOnlyPublicKey::from_str(hex).map_err(|e| VaultError::NumsKeyParse(e.to_string()))
}

/// Derive a simple single-admin vault address: `tr(NUMS, {pk(admin)})`.
///
/// This is the **pilot vault** — a Taproot address with:
/// - NUMS internal key (key-path unspendable — wallet cannot sweep via coin selection)
/// - Single Tapscript leaf `pk(admin)` (admin can spend via script-path, e.g. for chaining)
///
/// No committee keys required — suitable for single-operator institutions.
/// The full `VaultPolicy` (with CSV delay + committee) is for production multi-sig custody.
///
/// The returned address is written into the institution inscription body as `"vault": "tb1p…"`
/// so the protocol has an on-chain declaration of the custody address. The inscription sat
/// itself stays at `change_address` for indexer discoverability.
pub fn admin_vault_address(
    admin: &XOnlyPublicKey,
    network: Network,
) -> Result<String, VaultError> {
    let nums = XOnlyPublicKey::from_str(NUMS_KEY_HEX)
        .map_err(|e| VaultError::NumsKeyParse(e.to_string()))?;

    let policy_str = format!("pk({})", admin);
    let policy = Concrete::<XOnlyPublicKey>::from_str(&policy_str)
        .map_err(|e| VaultError::Compile(e.to_string()))?;
    let descriptor = policy
        .compile_tr(Some(nums))
        .map_err(|e| VaultError::Compile(e.to_string()))?;

    derive_address(&descriptor, network)
}

// ---------------------------------------------------------------------------
// WASM exports (Step 2.2)
// ---------------------------------------------------------------------------

#[cfg(feature = "wasm")]
pub mod wasm {
    use super::*;
    use wasm_bindgen::prelude::*;

    /// Derive the simple single-admin pilot vault address: `tr(NUMS, {pk(admin)})`.
    ///
    /// Returns a bech32m address string (`tb1p…` on testnet, `bc1p…` on mainnet).
    /// This is what gets written into `InstitutionBody.vault` at inscription time.
    #[wasm_bindgen]
    pub fn derive_admin_vault_address(
        admin_hex: &str,
        testnet: bool,
    ) -> Result<String, JsValue> {
        let admin = parse_xonly(admin_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let network = if testnet { Network::Testnet } else { Network::Bitcoin };
        super::admin_vault_address(&admin, network)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Generate a BINST vault descriptor from pubkey hex strings.
    ///
    /// Returns a JSON string:
    /// ```json
    /// {
    ///   "descriptor": "tr(NUMS,{…})",
    ///   "address": "tb1p…",
    ///   "spending_paths": [
    ///     { "name": "…", "required_keys": ["…"], "timelock_blocks": 144, "witness_size": 137 }
    ///   ]
    /// }
    /// ```
    #[wasm_bindgen]
    pub fn generate_vault_descriptor(
        admin_hex: &str,
        committee_a_hex: &str,
        committee_b_hex: &str,
        committee_c_hex: &str,
        csv_delay: u16,
        testnet: bool,
    ) -> Result<String, JsValue> {
        let policy = VaultPolicy {
            admin: parse_xonly(admin_hex).map_err(|e| JsValue::from_str(&e.to_string()))?,
            committee: [
                parse_xonly(committee_a_hex).map_err(|e| JsValue::from_str(&e.to_string()))?,
                parse_xonly(committee_b_hex).map_err(|e| JsValue::from_str(&e.to_string()))?,
                parse_xonly(committee_c_hex).map_err(|e| JsValue::from_str(&e.to_string()))?,
            ],
            csv_delay,
        };

        let desc = policy.compile().map_err(|e| JsValue::from_str(&e.to_string()))?;

        let address = if testnet {
            &desc.address_testnet
        } else {
            &desc.address_mainnet
        };

        // Build JSON manually to avoid pulling in serde_json for simple output
        let paths_json: Vec<String> = desc
            .spending_paths
            .iter()
            .map(|p| {
                let keys: Vec<String> = p.required_keys.iter().map(|k| format!("\"{}\"", k)).collect();
                let tl = match p.timelock_blocks {
                    Some(b) => format!("{}", b),
                    None => "null".into(),
                };
                format!(
                    "{{\"name\":\"{}\",\"required_keys\":[{}],\"timelock_blocks\":{},\"witness_size\":{}}}",
                    p.name,
                    keys.join(","),
                    tl,
                    p.witness_size,
                )
            })
            .collect();

        let json = format!(
            "{{\"descriptor\":\"{}\",\"address\":\"{}\",\"spending_paths\":[{}]}}",
            desc.descriptor.replace('\"', "\\\""),
            address,
            paths_json.join(","),
        );

        Ok(json)
    }
}

// ---------------------------------------------------------------------------
// Tests (Step 1.4)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Demo keys from taproot-vault.ts
    const ADMIN_HEX: &str =
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const COMMITTEE_A_HEX: &str =
        "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const COMMITTEE_B_HEX: &str =
        "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    const COMMITTEE_C_HEX: &str =
        "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13";

    fn demo_policy() -> VaultPolicy {
        VaultPolicy {
            admin: parse_xonly(ADMIN_HEX).unwrap(),
            committee: [
                parse_xonly(COMMITTEE_A_HEX).unwrap(),
                parse_xonly(COMMITTEE_B_HEX).unwrap(),
                parse_xonly(COMMITTEE_C_HEX).unwrap(),
            ],
            csv_delay: DEFAULT_CSV_DELAY,
        }
    }

    #[test]
    fn admin_vault_address_testnet() {
        let admin = parse_xonly(ADMIN_HEX).unwrap();
        let addr = super::admin_vault_address(&admin, Network::Testnet).unwrap();
        assert!(
            addr.starts_with("tb1p"),
            "expected tb1p…, got {addr}"
        );
    }

    #[test]
    fn admin_vault_address_differs_from_full_vault() {
        let admin = parse_xonly(ADMIN_HEX).unwrap();
        let pilot_addr = super::admin_vault_address(&admin, Network::Testnet).unwrap();
        let full_addr = demo_policy().compile().unwrap().address_testnet;
        assert_ne!(
            pilot_addr, full_addr,
            "pilot vault (no committee) should differ from full vault"
        );
    }

    #[test]
    fn compile_produces_descriptor() {
        let desc = demo_policy().compile().unwrap();
        assert!(desc.descriptor.starts_with("tr("));
        assert!(desc.descriptor.contains(NUMS_KEY_HEX));
    }

    #[test]
    fn testnet_address_starts_with_tb1p() {
        let desc = demo_policy().compile().unwrap();
        assert!(
            desc.address_testnet.starts_with("tb1p"),
            "expected tb1p…, got {}",
            desc.address_testnet
        );
    }

    #[test]
    fn mainnet_address_starts_with_bc1p() {
        let desc = demo_policy().compile().unwrap();
        assert!(
            desc.address_mainnet.starts_with("bc1p"),
            "expected bc1p…, got {}",
            desc.address_mainnet
        );
    }

    #[test]
    fn csv_delay_one_compiles() {
        let mut policy = demo_policy();
        policy.csv_delay = 1;
        // Minimum valid CSV delay
        let desc = policy.compile().unwrap();
        assert!(desc.descriptor.starts_with("tr("));
    }

    #[test]
    fn csv_delay_zero_rejected() {
        let mut policy = demo_policy();
        policy.csv_delay = 0;
        // Miniscript requires relative locktimes >= 1
        assert!(policy.compile().is_err());
    }

    #[test]
    fn analyze_returns_two_paths() {
        let paths = demo_policy().analyze();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].name, "Admin (CSV-delayed)");
        assert_eq!(paths[1].name, "Committee (immediate)");
    }

    #[test]
    fn admin_path_has_timelock() {
        let paths = demo_policy().analyze();
        assert_eq!(paths[0].timelock_blocks, Some(DEFAULT_CSV_DELAY));
        assert_eq!(paths[0].required_keys.len(), 1);
    }

    #[test]
    fn committee_path_is_immediate() {
        let paths = demo_policy().analyze();
        assert_eq!(paths[1].timelock_blocks, None);
        assert_eq!(paths[1].required_keys.len(), 3);
    }

    #[test]
    fn witness_sizes_are_reasonable() {
        let paths = demo_policy().analyze();
        for path in &paths {
            assert!(
                path.witness_size < 200,
                "{}: witness {} >= 200",
                path.name,
                path.witness_size
            );
        }
    }

    #[test]
    fn descriptor_round_trips() {
        let desc = demo_policy().compile().unwrap();
        // Parse the descriptor string back and verify it re-serializes identically
        let parsed: Descriptor<XOnlyPublicKey> =
            Descriptor::from_str(&desc.descriptor).unwrap();
        assert_eq!(parsed.to_string(), desc.descriptor);
    }

    #[test]
    fn address_accessor_works() {
        let desc = demo_policy().compile().unwrap();
        assert!(desc.address(Network::Bitcoin).starts_with("bc1p"));
        assert!(desc.address(Network::Testnet).starts_with("tb1p"));
    }
}
