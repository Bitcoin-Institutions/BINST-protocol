# How BINST Represents Institutions on Bitcoin

A non-technical explanation of how the BINST protocol makes institutions,
membership, and processes **fully visible and verifiable on Bitcoin** —
without requiring custom software for basic discovery.

---

## The big picture

BINST is a protocol for creating and operating transparent institutions on
Bitcoin. **The Bitcoin key is the root of authority.** The user who holds the
private key controls everything — the institution's identity, its membership,
and any L2 contracts that execute logic on its behalf.

It uses three complementary Bitcoin-native mechanisms:

1. **Ordinals inscriptions** — each institution, process template, and
   process instance is a unique inscription on Bitcoin, discoverable in
   any Ordinals explorer or wallet. **The inscription UTXO owner is the
   canonical admin.**
2. **Runes** — institutional membership is a fungible token on Bitcoin,
   visible in any Rune-aware wallet
3. **L2 smart contracts** — complex institutional logic (multi-step workflows,
   payment processing, validation rules) executes on an L2 as a **delegate**
   of the Bitcoin key holder. Currently Citrea, but portable to any L2.

```
┌─────────────────────────────────────────────────┐
│        BITCOIN (L1) — ROOT OF AUTHORITY          │
│                                                 │
│  Ordinals         Runes         Batch Proofs    │
│  (identity)       (membership)  (verification)  │
│  ★AUTHORITATIVE★                                │
│  "it exists and   "I'm a        "every state    │
│   I own it"       member"       transition was   │
│                                 correct"        │
└─────────────────────────────────────────────────┘
                      │
         L2 processing layer (DELEGATE)
         Currently Citrea — portable to any L2
         Smart contracts execute here
         Complex logic, events, payments
```

---

## Three ways to find BINST entities on Bitcoin

### 1. Ordinal inscriptions — entity identity and provenance

Every BINST entity is inscribed on Bitcoin as an Ordinal. The inscription
carries the entity's metadata (name, admin key, description) and sits in a
UTXO controlled by the admin's Bitcoin key. The Ordinals `metaprotocol` field
is set to `"binst"`, making all BINST entities filterable by any indexer.

Entities form a parent/child hierarchy — an institution is a child of the
BINST root inscription, a process template is a child of its institution,
and so on. This provenance is trustlessly verifiable by anyone running `ord`.

```
BINST Root Inscription (parent)
 ├── Institution "Acme Financial" (child)
 │    ├── Process Template "KYC Onboarding" (grandchild)
 │    │    ├── Instance #1 (great-grandchild)
 │    │    │    ├── Step 1 executed by Alice (event)
 │    │    │    └── Step 2 executed by Bob (event)
 │    │    └── Instance #2
 │    └── Process Template "Loan Approval"
 └── Institution "Bitcoin Credit Union" (child)
```

**How to find them:**
- Any Ordinals explorer (ordinals.com, ord.io, Hiro) — search by metaprotocol
- Any Ordinals wallet (Xverse, Unisat) — the institution shows up as an asset
- Self-hosted `ord` indexer — trustless, full access to all inscriptions
- **No custom BINST software needed for basic discovery**

**Ownership:** whoever controls the UTXO holding the inscription controls the
institution. Transfer the UTXO = transfer admin rights. This is pure
Bitcoin-native ownership and the **root of authority** for the entire protocol.
L2 contracts are delegates that execute logic on behalf of this key holder.
If the user switches L2s, the identity stays on Bitcoin.

**Updates:** reinscription appends to the inscription's history (the first
inscription is canonical, reinscriptions form an append-only changelog).
This matches BINST's transparency requirement — institutions cannot erase
their history.

### 2. Runes — membership tokens

Each institution etches a Rune (e.g., `ACME•MEMBER`) that represents
membership. Holding ≥1 unit means "you are a member."

**How to check membership:**
- Any Rune-aware wallet (Xverse, Unisat) — "I hold ACME•MEMBER"
- Any Rune indexer — query balance of a specific address
- Self-hosted `ord` — trustless Rune balance verification
- **No custom BINST software needed**

**Adding a member:** admin sends 1 unit of the institution's Rune to the
new member's Bitcoin address. **Removing:** admin burns the token or member
sends it back. This mirrors the Solidity `addMember`/`removeMember` pattern
but lives entirely on Bitcoin L1.

### 3. L2 batch proofs — computational verification

Complex institutional logic (step execution, payment processing, multi-step
workflows) runs on L2 smart contracts **as a delegate of the Bitcoin key
holder**. The current L2 (Citrea) periodically writes **ZK batch proofs** to
Bitcoin — mathematical guarantees that every state transition was computed
correctly.

This is the **strongest verification layer**: anyone with a Bitcoin full node
and our `taproot-reader` tool can independently verify that every
institutional action was valid, without trusting the L2 at all.

The protocol is **L2-portable**: because the identity lives on Bitcoin (not
on any particular L2), the user can redeploy to a different L2 at any time.
The inscription, the Rune, and the provenance chain stay on Bitcoin unchanged.

**How batch proofs reach Bitcoin:** The L2 writes two kinds of data into
Bitcoin transactions via Taproot script-path spends:

- **Sequencer commitments** — fingerprints (Merkle roots) of batches of L2
  blocks, proving ordering
- **Batch proofs** — ZK proofs plus state diffs (every storage value that
  changed), proving correctness

The `taproot-reader` tool decodes these and maps storage slot changes back
to BINST entity fields (institution name, members, step states, etc.).

---

## Discovering BINST entities: who needs what

| What you want to know | Where to look | Software needed |
|---|---|---|
| Does institution X exist? | Ordinals explorer | Browser |
| Who is the admin? | Check UTXO owner of the inscription | Ordinals wallet or explorer |
| Am I a member? | Check Rune balance | Any Rune-aware wallet |
| Who are the members? | Query Rune balances | Rune indexer |
| What processes does it have? | Child inscriptions of the institution | Ordinals explorer |
| What step is instance Y on? | Citrea RPC or batch proof decode | Citrea RPC or taproot-reader |
| Was step execution valid? | ZK batch proof verification | Full node + taproot-reader |

The key insight: **basic discovery requires no custom software**. Standard
Ordinals and Rune tooling covers identity, ownership, and membership.
The full node + taproot-reader is only needed for the strongest verification
level — confirming that computations were correct via ZK proofs.

---

## How the protocol maps to Bitcoin

| Protocol entity | Bitcoin representation | How to find it |
|---|---|---|
| **Institution** | Ordinal inscription (metaprotocol: `binst`) | Ordinals explorer, wallet, `ord` |
| **Institution admin** | UTXO holder of the inscription | Check inscription ownership |
| **Membership** | Rune balance (`INSTITUTION•MEMBER`) | Rune wallet, indexer |
| **Process template** | Child inscription of institution | Ordinals explorer (provenance chain) |
| **Process instance** | Child inscription of template | Ordinals explorer (provenance chain) |
| **Step execution** | Child inscription of instance (optional) | Ordinals explorer |
| **Computational state** | Storage slots in Citrea batch proof state diffs | taproot-reader + full node |
| **State correctness** | ZK proof anchored to Bitcoin | taproot-reader + full node |

---

## The `BitcoinIdentity` type

Every BINST entity in the decoder carries a `BitcoinIdentity` — a struct
that links the entity across all reachability layers:

```
BitcoinIdentity {
    bitcoin_pubkey:      [u8; 32]        ← Taproot x-only key — ROOT OF AUTHORITY
    inscription_id:      Option<String>  ← Ordinals ID (e.g., "abc123...i0")
    membership_rune_id:  Option<String>  ← Rune ID (e.g., "840000:20")
    evm_address:         Option<[u8;20]> ← L2 contract address (delegate, can change)
    derivation_hint:     Option<String>  ← HD wallet path (e.g. m/86'/0'/0'/0/0)
}
```

The ordering reflects the authority hierarchy:
1. `bitcoin_pubkey` — the root of authority (controls the inscription UTXO) — **required**
2. `inscription_id` — the entity's permanent identity on Bitcoin
3. `membership_rune_id` — membership token on Bitcoin
4. `evm_address` — the current L2 processing delegate (**optional** — can change if L2 changes)

---

## When is a full Bitcoin node needed?

A full node is **not required** for basic discovery of BINST entities.
Standard Ordinals and Rune tooling handles identity, ownership, and
membership.

A full node **is required** for:

1. **ZK proof verification** — independently confirming that Citrea's
   state transitions were computed correctly by decoding batch proofs
   from raw witness data
2. **Trustless mode** — not relying on any third-party explorer or indexer
3. **Scanning Citrea DA transactions** — the `taproot-reader` tool
   connects to a local Bitcoin Core node to scan for Citrea's Taproot
   script-path spends

Think of it as two tiers:

```
Tier 1 (standard tooling):  Ordinals explorer + Rune wallet
  → identity, ownership, membership — no full node needed

Tier 2 (verification):  Bitcoin full node + taproot-reader
  → ZK proof verification, state diff decoding — trustless
```

For the BINST pilot, the full node runs on the developer's home server
connected to Bitcoin Testnet4.

---

## Summary

BINST entities are fully represented on Bitcoin through three mechanisms:

1. **Ordinals** — each entity is an inscription, owned by a Bitcoin key,
   discoverable in any Ordinals explorer or wallet. **The Bitcoin key is
   the root of authority.**
2. **Runes** — membership is a token balance, visible in any Rune-aware wallet
3. **Batch proofs** — every computation is ZK-proven and anchored to Bitcoin

A Bitcoin maximalist can:
- See the institution in their Ordinals explorer ✓
- See their membership in their Rune wallet ✓
- Verify the institution's entire computational history with a full node ✓
- Never touch any specific L2 directly if they don't want to ✓
- Move their institution to a different L2 without losing identity ✓
- Have their institution **visible on multiple L2s simultaneously** via
  LayerZero V2 mirrors (identity/membership) and Bitcoin DA (execution proofs) ✓

The L2 is a processing delegate, not the owner. The user's Bitcoin key
controls everything. Cross-chain presence uses two sync channels:
**LayerZero V2** for real-time identity sync, **Bitcoin DA** for trustless
execution verification. Process instances have a single home chain —
mirrors are read-only to prevent concurrent mutation conflicts.

### Crate architecture

```
taproot-reader/
  crates/
    citrea-decoder/    ← Citrea DA inscription parser (no_std, WASM-ready)
    binst-decoder/     ← Storage slots → protocol entities (BitcoinIdentity-aware)
                         includes value.rs: human-readable decoding
                         (addresses, uints, bools, strings, StepState structs)
                         with Citrea LE→BE word reversal
                         includes vault.rs: BIP 379 miniscript policy →
                         Taproot descriptor compilation (WASM-exportable)
    cli/               ← citrea-scanner binary (connects to Bitcoin Core RPC
                         or Citrea RPC; supports --discover)
```

### Wallet-compatible vault protection

Inscription UTXOs are protected by miniscript spending policies compiled
to Taproot descriptors. The descriptor `tr(NUMS, {and(pk(admin),older(144)), thresh(2,pk(A),pk(B),pk(C))})`
is importable into standard Bitcoin wallets (Sparrow, Liana, Nunchuk) —
no custom BINST software is needed to sign vault spends.

See `MINISCRIPT.md` for the vault architecture.
See `BITCOIN-IDENTITY.md` for the full architecture specification.
See `DECODING.md` for Citrea DA transaction format details.