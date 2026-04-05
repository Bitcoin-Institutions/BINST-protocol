# Decoding Citrea Data-on-DA (DECODING.md)

This document explains the technical details of decoding Citrea Data Availability
inscriptions written into Bitcoin taproot script-path transactions. It covers the
five transaction types, the wire format, and the practical steps for finding and
decoding them.

**Context:** This is the verification layer of the BINST protocol. For basic
discovery of institutions, membership, and provenance, use Ordinals explorers
and Rune indexers (see `conceptual.md`). This document covers the deeper layer:
decoding Citrea's ZK batch proofs and state diffs from raw Bitcoin witness data,
which requires a Bitcoin full node and our `taproot-reader` tool.

## Goals

- Explain the five Citrea DA variants and their encoded payloads.
- Describe how Citrea puts data into Bitcoin (tapscript witness format, wtxid prefix, nonce).
- Provide a concrete, reliable procedure for finding, extracting, and decoding inscriptions.
- Point to the code that implements parsing and scanning in this repository.

---

## Overview — the five DataOnDa transaction types

Citrea serializes a top-level Borsh enum called `DataOnDa` and places it inside a taproot script-path reveal. The variants we expect are:

1. **Complete** (variant 0)
   - Compressed ZK batch proof. Stored as `Complete(Vec<u8>)`.
   - Fits entirely inside a single tapscript body when small enough (< ~397 KB practical limit).

2. **Aggregate** (variant 1)
   - Lists referencing chunk transactions when a full proof is too large.
   - Stored as `Aggregate(Vec<[u8;32]>, Vec<[u8;32]>)` — typically `txids` and `wtxids`. The exact meaning follows Citrea's on-chain convention.

3. **Chunk** (variant 2)
   - A fragment of a large proof. Stored as `Chunk(Vec<u8>)`.
   - Chunks are referenced from an Aggregate entry and reassembled off-chain by the client.

4. **BatchProofMethodId** (variant 3)
   - Security-council / method-ID metadata plus signatures. Stored as `BatchProofMethodId(BatchProofMethodIdData)` where `BatchProofMethodIdData` contains a `method_id`, a vector of signatures, and public keys.

5. **SequencerCommitment** (variant 4)
   - The most common type: a compact commitment posted by the sequencer that anchors an L2 batch to Bitcoin.
   - Stored as `SequencerCommitment { merkle_root: [u8;32], index: u32, l2_end_block_number: u64 }`.

Note: Borsh uses a 1-byte discriminant for enum variants in this encoding (empirically verified). That first byte inside the Borsh payload identifies the variant (0..4).

---

## How Citrea writes data to Bitcoin (the reveal tapscript)

Citrea uses a taproot script-path spend where the tapscript (in the witness) follows a compact, structured layout. The important parts (in order) are:

```text
PUSH32 <x_only_pubkey>           32 bytes — the DA pubkey used by Citrea
OP_CHECKSIGVERIFY
PUSH2  <kind_bytes_le>           2 bytes LE — transaction kind (u16)
OP_FALSE
OP_IF
  PUSH <schnorr_signature>       64 bytes normally
  PUSH <signer_pubkey>           33 bytes (compressed)
  PUSH <body_chunk> ...          one or many pushdata entries, concatenated
OP_ENDIF
PUSH8  <nonce_le>                8 bytes LE — nonce used for wtxid mining
OP_NIP
```

The `body_chunk` bytes concatenated form a Borsh-serialized `DataOnDa` value.

Why a nonce? the tapscript witness affects the transaction witness and thus the wtxid. The sequencer picks a nonce so that the resulting wtxid starts with a chosen prefix (Citrea uses `0x0202` in production; `0x02` for some testing). This creates a compact on-chain marker that quickly identifies reveal transactions.

---

## What we look for in Bitcoin

1. **wtxid prefix** — Citrea uses a deterministic reveal prefix (production `0x02 0x02`). The wtxid is computed over the full serialized transaction including witness data (double-SHA256). The prefix is taken from the first bytes of the result.

2. **Script-path Taproot spends** — the reveal sits in the tapscript, which is the second-to-last witness element of a script-path spend (witness stack: `[args..., tapscript, control_block]`).

3. **Tapscript structure** — a `PUSH32` pubkey followed by `OP_CHECKSIGVERIFY` and the structured envelope shown above.

4. **Borsh payload** — once the body bytes are concatenated they must Borsh-deserialize to `DataOnDa`. The first byte of the body is the 1-byte enum discriminant (0–4).

---

## When and why to use a full Bitcoin node

**A full node is NOT required for basic BINST entity discovery.** Institutions,
membership, and provenance are represented as Ordinals inscriptions and Rune
balances, discoverable through standard explorers and wallets (see `conceptual.md`
and `BITCOIN-IDENTITY.md`).

**A full node IS required for ZK verification** — independently confirming that
Citrea's state transitions were computed correctly by decoding batch proofs from
raw witness data. This is the trustless verification tier.

When running this verification tier, a full node provides:

- **Full witness data access.** Batch proofs live inside taproot witness fields.
  Many public APIs strip or truncate witness data.

- **Consensus verification.** A full node validates blocks locally, preventing
  inconsistent or reorged data from third-party APIs.

- **Performance.** Local RPC calls are fast and unmetered. Public APIs impose
  rate limits.

- **Privacy.** No query telemetry is leaked to third parties.

- **Reorg handling.** A full node detects reorgs and verifies inclusion at
  specific block heights.

---

## Practical procedure to find and decode Citrea inscriptions

This section gives a step-by-step operational flow. See `taproot-reader/crates/cli/src/main.rs` and `taproot-reader/crates/citrea-decoder/src/parser.rs` for a production implementation.

### 1) Choose a scanning strategy

- Tip-based (continuous): from (last_seen + 1) to current tip. Use `getblockchaininfo` to find tip height.
- Range scan (investigation): `--from`/`--to` flags to scan a specific historical range.
- Targeted block checks: only query blocks with `nTx > 1` (many testnet blocks are coinbase-only). Use `getblockheader` to cheaply sample `nTx` before fetching full blocks.

### 2) Fetch the block

- Use `get_block_hash(height)` then `get_block(block_hash)` to obtain the full block with `tx` entries (contains witness info in modern `bitcoind` clients when the RPC client requests full blocks).

### 3) Iterate transactions (skip coinbase)

- For each transaction, serialize it with witness included and compute `wtxid` := double-SHA256(serialized_tx_with_witness).
- Filter by prefix: check whether `wtxid.starts_with(REVEAL_TX_PREFIX)` (production `0x02 0x02`). If not, skip.

### 4) Extract tapscript

- For script-path spends, the witness stack recorded by the node contains the `tapscript` as the second-to-last element. Extract `witness[witness.len() - 2]`.
- If witness size < 2, it's not a script-path spend — skip.

### 5) Parse structured tapscript

Walk the pushdata opcodes in the order described in the [tapscript layout](#how-citrea-writes-data-to-bitcoin-the-reveal-tapscript) section above. The parser must be resilient to `OP_PUSHDATA1` / `OP_PUSHDATA2` encodings and must concatenate multiple body chunks before Borsh decoding.

### 6) Deserialize the body with Borsh

- The `body` bytes are `borsh(DataOnDa)`. The first byte is the discriminant (0..4). Call Borsh deserialization to get a typed `DataOnDa` value.
- For `SequencerCommitment` (variant 4), expect a 32-byte merkle root, 4-byte little-endian index, and 8-byte little-endian L2 end block number.

### 7) Map decoded payloads to protocol events and entities

- SequencerCommitment -> a new L2 batch has been finalized up to `l2_end_block_number`. The `index` (monotonic) and `merkle_root` can be used to anchor or verify L2 state.
- Complete -> a ZK batch proof was posted; clients can download and verify the proof to confirm correctness of a prior batch.
- Aggregate + Chunk -> reassembly instructions and data for large proofs. Use referenced `txid/wtxid` values to fetch the chunk transactions and reconstruct the full proof.
- BatchProofMethodId -> security council / method-id update: verify listed signatures against known signers if required by your governance.

---

## Examples — commands and usage

Using a local node (example with the project's testnet4 config):

```bash
# get tip height
bitcoin-cli -conf=$HOME/.bitcoin/bitcoin-testnet4.conf getblockchaininfo

# get block hash then block with witness
bitcoin-cli -conf=$HOME/.bitcoin/bitcoin-testnet4.conf getblockhash 127600
bitcoin-cli -conf=$HOME/.bitcoin/bitcoin-testnet4.conf getblock <blockhash> 2

# get raw tx with verbose output (contains vin[].txinwitness)
bitcoin-cli -conf=$HOME/.bitcoin/bitcoin-testnet4.conf getrawtransaction <txid> true
```

We provide a convenience CLI to automate the scanning/decoding: `taproot-reader/crates/cli/` (`citrea-scanner`). Example usage:

### Bitcoin Core mode (local full node)

```bash
# Scan a single block (uses cookie auth by default)
cargo run --bin citrea-scanner -- --block 127600

# Scan a range with explicit auth
cargo run --bin citrea-scanner -- --from 127600 --to 127761 --format json \
  --rpc-user <user> --rpc-pass <pass>
```

### Citrea RPC mode (no Bitcoin node required)

```bash
# Query batch proofs directly from Citrea, with auto-discovery of BINST contracts
cargo run --bin citrea-scanner -- \
  --citrea-rpc https://rpc.testnet.citrea.xyz \
  --discover \
  --deployer 0xd0abca83bd52949fcf741d6da0289c5ec7235aaf \
  --block 127848

# Manual contract addresses (skip discovery)
cargo run --bin citrea-scanner -- \
  --citrea-rpc https://rpc.testnet.citrea.xyz \
  --deployer 0x... --template 0x... --instance 0x... \
  --from 127840 --to 127850
```

The `--discover` flag crawls the deployer contract on-chain:
`deployer.getInstitutions()` → `institution.getProcesses()` → `template.getAllInstances()`.

---

## Human-readable value decoding

Once BINST storage slot changes are identified in a state diff, the raw hex
values are decoded into human-readable form by the `value` module in
`binst-decoder`.

### Citrea little-endian word order (key discovery)

**Citrea / Sovereign SDK stores EVM storage values in little-endian word
order.** The entire 32-byte slot value is byte-reversed compared to the
standard Solidity ABI encoding used by geth/mainnet Ethereum.

Example — the uint256 value `1`:
- Standard Solidity (BE): `0x0000000000000000000000000000000000000000000000000000000000000001`
- Citrea state trie (LE): `0x0100000000000000000000000000000000000000000000000000000000000000`

The decoder pads the raw value to 32 bytes (state diffs may trim trailing LE
zeros) and reverses before interpreting according to the field's Solidity type.

### Decoded type examples

From real block 127848 (19 BINST state changes):

```
ProcessTemplate.name = "KYC Verification"          ← short Solidity string decoded inline
ProcessTemplate.description = <string, 62 bytes>    ← long string (data at keccak(slot))
ProcessTemplate.creator = 0x46c505d38e9009a16398f268e26dff6844ef59d5
ProcessTemplate.steps.length = 4
ProcessTemplate.instantiationCount = 1
ProcessInstance.creator = 0x8cf6fe5cd0905b6bfb81643b0dcda64af32fd762
ProcessInstance.currentStepIndex = 4
ProcessInstance.totalSteps = 4
ProcessInstance.completed = true
ProcessInstance.createdAt = 1774750572
ProcessInstance.stepStates[0] = Completed by 0x8cf6fe5cd0905b6bfb81643b0dcda64af32fd762
BINSTDeployer.institutions[0] = 0x3a6a07c5d2c420331f68dd407aafff92f3275a86
```

### Supported Solidity types

| Solidity type | SlotType | Decoding |
|---|---|---|
| `address` | `Address` | Last 20 bytes of BE word → `0x…` |
| `uint256` | `Uint256` | Big-endian → decimal string |
| `bool` | `Bool` | `0` → `false`, non-zero → `true` |
| `bytes32` | `Bytes32` | Full 32 bytes → `0x…` hex |
| `string` (≤31 chars) | `SolString` | Inline: high bytes = data, low byte / 2 = length |
| `string` (>31 chars) | `SolString` | Low bit = 1 → `<string, N bytes>` (data at `keccak256(slot)`) |
| `StepState` struct | `StepState` | Packed: `word[31]` = status, `word[11..31]` = actor |

### Packed struct layout (StepState)

Solidity packs `uint8 status` + `address actor` right-aligned in one slot:

```
BE word (after LE→BE reversal):
  [00 × 11 bytes][actor × 20 bytes][status × 1 byte]
   ↑ padding      ↑ bytes 11..31    ↑ byte 31
```

Status values: `0` = Pending, `1` = Completed, `2` = Rejected.

---

## Important implementation notes and edge cases

- **Borsh discriminant is 1 byte.** Citrea uses a 1-byte enum index (empirically verified). Do not assume 4-byte discriminants.

- **Pushdata encodings.** Tapscripts may use `OP_PUSHBYTES_N`, `OP_PUSHDATA1`, or `OP_PUSHDATA2`. A robust parser must support all three.

- **Body chunking.** For very large payloads the body is split into ≤520-byte pushdata chunks; the parser must concatenate them in order before Borsh decoding.

- **Nonce length.** The nonce is normally `PUSH8` (8 bytes LE), but handle variable-length pushdata defensively when computing the numeric nonce value.

- **Signature and signer formats.** Signatures are typically 64-byte Schnorr; signer pubkeys are compressed (33 bytes). Be tolerant but validate lengths.

- **wtxid vs txid.** Citrea uses the wtxid (witness txid) prefix as the marker. The txid (non-witness hash) is different. Always compute the wtxid over the full serialization with witness included.

- **Reorg handling.** Treat recently-inscribed reveals as provisional until they have sufficient confirmations; a full node helps detect reorgs.

- **Privacy and rate limiting.** Iterating large ranges against remote public APIs can be slow, metered, and leak sensitive query patterns. Use a local node for production scanning.

- **Authority of data.** Only rely on data present in blocks that your own node has validated. Do not accept third-party API results without independent verification.

---

## Links to the implementation in this repository

- Taproot scanner CLI: `taproot-reader/crates/cli/src/main.rs` — scanning strategy, RPC usage, wtxid computation, extraction and printing.
- Parser and types: `taproot-reader/crates/citrea-decoder/src/parser.rs` and `taproot-reader/crates/citrea-decoder/src/types.rs` — precise tapscript parser and Borsh type definitions.

---

## Recommended next steps / improvements

- Add unit tests for each `DataOnDa` variant using crafted Borsh payloads.

- Add fuzz tests for the tapscript parser to ensure robust handling of malformed pushdata.

- Add a reassembly helper for `Aggregate` + `Chunk` flow: given an `Aggregate` record, fetch and verify all referenced chunk transactions and reassemble the proof.

- Export a WASM build of `citrea-decoder` so a lightweight indexer (browser or edge) can decode batch proofs without running a full node.

- ~~Implement a state-diff parser for `Complete` batch proofs — extracting `(contract, slot, old_value, new_value)` tuples from the raw proof bytes.~~ **Done** — `binst-decoder` crate decodes JMT keys, builds forward-hash lookup tables, and maps state diffs to BINST slots.

- ~~Integrate with the `binst-decoder` crate to map decoded state diffs to BINST protocol entities (institutions, templates, instances).~~ **Done** — `map_state_diff()` identifies BINST changes; `--discover` auto-discovers all contract addresses from the deployer.

- ~~Add human-readable value decoding for state diff values (addresses, integers, booleans, strings, packed structs).~~ **Done** — `value.rs` module decodes raw Citrea LE storage values to human-readable form. Key finding: Citrea stores EVM slot values in little-endian word order (entire 32-byte word byte-reversed). Verified against real block 127848.

Note: this document covers the verification tier only. For the entity identity
and membership layers (Ordinals + Runes), see `BITCOIN-IDENTITY.md`.

---

## Short checklist — scanning safety

- [x] Use a local Bitcoin Core with `txindex=1` (optional) if you need historical getrawtransaction access.
- [x] Prefer cookie or env-var auth to avoid exposing RPC credentials in code or CLI history.
- [ ] Keep a tip cursor and checkpoint last-scanned block to avoid re-scanning.
- [ ] Rate-limit parallel RPC requests to avoid overloading the node.