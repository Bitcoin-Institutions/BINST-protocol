# BINST Protocol

**Bitcoin-native institutional identity and process execution.**

BINST is a metaprotocol that anchors institutional identity on Bitcoin (via Ordinals inscriptions) and executes business processes on EVM rollups (Citrea), with full Bitcoin settlement finality.

This repository is the core Rust workspace — 6 crates covering the entire protocol stack from raw Bitcoin witness parsing to EVM ABI encoding and a sovereign CLI toolkit.

## Architecture

```
Bitcoin L1 (Testnet4)                    Citrea L2 (Testnet, chain 5115)
┌─────────────────────┐                  ┌──────────────────────────┐
│  Ordinals Inscriptions │                │  BINSTProcessFactory     │
│  ┌─────────────────┐  │                │  ├── createInstance()    │
│  │ Institution      │  │   anchor       │  └── getTemplateInstances()│
│  │  └─ ProcessTemplate│◄──────────────►│  BINSTProcess            │
│  │      └─ children │  │  inscription   │  ├── executeStep()      │
│  └─────────────────┘  │  ID            │  ├── currentStepIndex()  │
│                        │                │  └── completed()         │
│  Commit → Reveal PSBT  │                │                          │
│  Mempool.space API     │                │  Sequencer → Committed   │
└─────────────────────┘                  │  → ZK Proven on Bitcoin  │
                                          └──────────────────────────┘
```

**Design principle: Thin L2, Fat L1.** Bitcoin is the source of truth for identity (institutions) and definitions (process templates). The L2 only holds execution state. This enables cross-chain migration — a partially-executed process can move between L2s carrying only its template inscription ID.

## Crates

| Crate | Description | `no_std` | WASM |
|---|---|---|---|
| [`binst-inscription`](crates/binst-inscription/) | Ordinals envelope parser for the `binst` metaprotocol | ✅ | ✅ |
| [`binst-decoder`](crates/binst-decoder/) | Map Citrea DA state diffs → protocol entities; miniscript vault | ✅* | ✅ |
| [`binst-evm`](crates/binst-evm/) | ABI encoding/decoding + JSON-RPC client for BINST contracts | ✅ | ✅ |
| [`binst-btc`](crates/binst-btc/) | Bitcoin inscription pipeline — PSBT construction, broadcast | ✅ | ✅ |
| [`citrea-decoder`](crates/citrea-decoder/) | Citrea DA inscription parser (sequencer commitments, batch proofs) | ✅ | ✅ |
| [`cli`](crates/cli/) | `binst` sovereign CLI toolkit | — | — |

\* `binst-decoder` uses `std` for the `vault` module (miniscript).

All library crates use feature gates: `std` for native HTTP (ureq), `wasm` for browser (web-sys/js-sys).

## CLI

```bash
cargo install --path crates/cli

# Query Bitcoin settlement finality
binst finality --tx 0xabc123...

# Inspect a deployed process instance
binst instance --address 0x5490...f7c9

# Derive a vault address from admin pubkey
binst vault --admin 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

# Query factory state
binst factory --template "abc123...i0"

# Scan Bitcoin blocks for Citrea DA inscriptions
binst scan --citrea-rpc https://rpc.testnet.citrea.xyz --block 127747
```

All subcommands support `--format json` for scripting.

## Metaprotocol

BINST inscriptions use the Ordinals envelope format with metaprotocol tag `binst`. Entity types:

| Type | Purpose | Linking |
|---|---|---|
| `institution` | Root identity anchor | — |
| `process_template` | Workflow definition (steps) | `institution_id` + parent tag 3 |
| `process_instance` | Execution record | `template_id` |
| `step_execution` | Evidence for a step | `instance_id` |
| `state_digest` | L2 state snapshot | `institution_id` |

Schema and examples: [`schema/`](schema/)

### Provenance chain

Inscriptions form an on-chain hierarchy via two mechanisms:
1. **Body fields** — `institution_id`, `template_id` in the JSON body
2. **Ordinals parent tag** (tag 3) — parent inscription sat spent as input in the child's reveal tx

This creates a verifiable chain: Institution → ProcessTemplate → ProcessInstance, anchored on Bitcoin.

## Vault

The pilot uses a single-admin vault descriptor:

```
tr(NUMS, {pk(admin)})
```

- **NUMS internal key** — key-path unspendable (wallet cannot sweep via coin selection)
- **Single Tapscript leaf** — admin can spend via script-path when needed
- Forward-compatible with covenant enforcement (OP_CTV/OP_CAT) when opcodes activate

The full committee vault (`VaultPolicy`) supports timelocked admin recovery + 2-of-3 committee emergency spend.

## Smart Contracts

Two active contracts on Citrea (thin L2 architecture):

| Contract | Address (Citrea testnet) | Purpose |
|---|---|---|
| `BINSTProcessFactory` | `0x6a1d...5000` | Deploys self-contained process instances |
| `BINSTProcess` | *(per-instance)* | Embedded steps + `templateInscriptionId` L1 anchor |

Source: [`binst-pilot/contracts/process/`](https://github.com/Bitcoin-Institutions/binst-pilot/tree/main/binst-pilot/contracts/process)

## Bitcoin Settlement Finality

Citrea transactions settle to Bitcoin through three tiers:

| Tier | Meaning | Finality |
|---|---|---|
| **Soft Confirmation** | Sequencer included the tx | Seconds |
| **Committed** | Batch posted to Bitcoin via DA inscription | ~10 min |
| **Proven** | ZK proof verified on Bitcoin | Hours–days |

The `binst finality` command and `binst-evm::FinalityTier` classify any L2 block or transaction.

## Testing

```bash
# Run all 106 tests
cargo test --workspace

# Run live Citrea testnet tests (requires network)
cargo test --workspace -- --ignored

# Run a specific crate
cargo test -p binst-evm
```

| Crate | Tests |
|---|---|
| `binst-btc` | 6 |
| `binst-decoder` | 54 + 5 e2e |
| `binst-evm` | 18 + 4 live (ignored) |
| `binst-inscription` | 11 |
| `citrea-decoder` | 7 |
| `cli` | 5 |
| **Total** | **106 passing** |

## Project Structure

```
binst-protocol/
├── Cargo.toml                    # Workspace root
├── schema/
│   ├── binst-metaprotocol.json   # JSON Schema for inscription bodies
│   └── examples/                 # Example inscription JSON files
└── crates/
    ├── binst-inscription/        # Envelope parser
    ├── binst-decoder/            # State diff decoder + vault
    ├── binst-evm/                # ABI + RPC client
    ├── binst-btc/                # PSBT + inscription pipeline
    ├── citrea-decoder/           # Citrea DA parser
    └── cli/                      # binst CLI binary
        └── src/
            ├── main.rs           # Clap subcommand dispatcher
            ├── scanner.rs        # Citrea DA block scanner
            └── cmd/              # Subcommand implementations
                ├── finality.rs
                ├── factory.rs
                ├── instance.rs
                ├── vault.rs
                └── scan.rs
```

## Related Repositories

| Repo | Purpose |
|---|---|
| [binst-pilot](https://github.com/Bitcoin-Institutions/binst-pilot) | Solidity contracts + TypeScript scripts (Hardhat) |
| [binst-pilot-webapp](https://github.com/Bitcoin-Institutions/binst-pilot-webapp) | Rust/WASM single-page app (source of truth for features) |
| [binst-pilot-docs](https://github.com/Bitcoin-Institutions/binst-pilot-docs) | mdbook documentation |

## Networks

| Network | Chain | RPC | Explorer |
|---|---|---|---|
| Bitcoin Testnet4 | — | Mempool.space API | [mempool.space/testnet4](https://mempool.space/testnet4) |
| Citrea Testnet | 5115 | `https://rpc.testnet.citrea.xyz` | [explorer.testnet.citrea.xyz](https://explorer.testnet.citrea.xyz) |

## License

Apache-2.0
