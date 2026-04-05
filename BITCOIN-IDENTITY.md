# BINST Bitcoin-Native Identity Architecture

How BINST entities are represented, discovered, and verified on Bitcoin.

---

## Overview

BINST uses three Bitcoin-native primitives to make institutional entities
fully stored and reachable on Bitcoin. **The Bitcoin key is the root of
authority.** L2 smart contracts (on Citrea or any future L2) are processing
delegates — they execute complex logic on behalf of the key holder, but
they do not own the identity.

| Primitive | Role | What it represents |
|---|---|---|
| **Ordinals inscriptions** | Entity identity, ownership, metadata | Institutions, process templates, process instances |
| **Runes** | Membership and fungible roles | "Alice is a member of Acme Financial" |
| **L2 smart contracts** | Computational processing (currently Citrea) | Step execution, payments, state transitions |

### Authority model: Bitcoin key is sovereign

```
Bitcoin secret key (ROOT OF AUTHORITY)
  │
  ├── controls inscription UTXO     → identity, provenance, metadata
  ├── controls Rune distribution    → membership tokens
  └── authorizes L2 contract(s)     → processing delegates
       ├── Citrea     (current)
       ├── Stacks     (possible future)
       ├── BOB        (possible future)
       └── any L2     (portable)
```

The user who holds the Bitcoin private key has **full control** of every
element in the protocol. If they decide to use a different L2, they can
deploy a new contract, point it at the same inscription ID, and pick up
where they left off. The inscription is the identity; the L2 is the
execution engine.

```
Bitcoin L1
├── Ordinals    → entities EXIST here (identity, ownership — AUTHORITATIVE)
├── Runes       → membership IS here (fungible tokens per institution)
└── ZK proofs   → computation is PROVEN here (L2 batch proofs)

Any L2 (currently Citrea)
└── Solidity    → complex logic EXECUTES here as a delegate of the BTC key holder
```

---

## Ordinals — entity identity and provenance

Each BINST entity is a permanent **Ordinals inscription on Bitcoin**.
The inscription is the entity's birth certificate, identity anchor, and
metadata carrier.

### Provenance hierarchy

Entities form a parent/child tree rooted at a single BINST root inscription:

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

Anyone running `ord` can verify the full provenance chain — "KYC Onboarding
was created by Acme Financial" — without touching Citrea.

### Inscription format

Every BINST inscription uses:
- **Metaprotocol** (tag 7) = `"binst"` — filterable by any indexer
- **Content type** = `application/json`
- **Metadata** (tag 5) = CBOR-encoded structured data
- **Parent** (tag 3) = parent inscription ID (provenance chain)

Example institution inscription:

```
OP_FALSE OP_IF
  OP_PUSH "ord"
  OP_PUSH 1                              ← content type tag
  OP_PUSH "application/json"             ← MIME type
  OP_PUSH 7                              ← metaprotocol tag
  OP_PUSH "binst"                        ← protocol identifier
  OP_PUSH 5                              ← metadata tag
  OP_PUSH <CBOR-encoded metadata>        ← structured metadata
  OP_PUSH 3                              ← parent tag
  OP_PUSH <binst-root-inscription-id>    ← provenance chain
  OP_PUSH 0                              ← body separator
  OP_PUSH '{
    "type": "institution",
    "name": "Acme Financial",
    "admin_btc_pubkey": "a3f4...x-only-32-bytes",
    "citrea_contract": "0x1234...5678",
    "created_btc_height": 127600,
    "members": ["pubkey1...", "pubkey2..."]
  }'
OP_ENDIF
```

### Ownership

The inscription UTXO is controlled by the admin's Bitcoin key. **This key
is the canonical authority** — whoever controls this UTXO controls the
institution, its child entities, and any L2 contracts bound to it.

- Transfer the UTXO = transfer admin rights (on Bitcoin and all L2s)
- L2 contracts derive their authority from this key, not the other way around
- A Bitcoin maximalist holds their institution in their Bitcoin wallet
- Switching L2s means deploying a new contract that references the same
  inscription ID — the identity stays on Bitcoin

### Updates via reinscription

The first inscription is canonical (per Ordinals protocol). Reinscriptions
**append** to the history — they do not overwrite. This is ideal for BINST:

- Inscription 1 (canonical): "Created Acme Financial, admin=pk1"
- Reinscription 2: "Updated description"
- Reinscription 3: "Admin transferred to pk2"

Institutions cannot erase their history. The append-only model matches
the transparency requirement.

Ownership transfer is a UTXO transfer, not a reinscription. The inscription
ID stays the same; the controlling key changes.

### UTXO safety: accidental spending risk

Because inscriptions are bound to specific UTXOs, an admin who spends
the inscription UTXO in a non-Ordinals-aware wallet (e.g., as part of
a regular payment or consolidation) **loses control of the inscription**.
The inscription data remains permanently on Bitcoin — it is never
destroyed — but the UTXO tracking it moves to an unknown party or
gets consumed as miner fees.

**Under the Bitcoin-key-sovereign model, this is the most critical risk
in the protocol.** The inscription UTXO is not a supplementary signal —
it is the root of authority. Losing it means losing control of the
institution at the Bitcoin layer. This is why the Taproot vault script
guard is not optional — it is essential infrastructure.

#### Script-level guard (Taproot vault)

Rather than relying solely on wallet discipline, BINST institution
inscriptions should be locked in a **Taproot script tree that prevents
accidental spending at the consensus level**.

The vault is defined as a [BIP 379](https://github.com/bitcoin/bips/blob/master/bip-0379.md) **miniscript policy**:

```
or(
  and(pk(admin), older(144)),       ← admin transfer, ~24h CSV delay
  thresh(2, pk(A), pk(B), pk(C))    ← 2-of-3 committee, immediate
)
```

This compiles to a Taproot descriptor via `rust-miniscript` (`binst-decoder/src/vault.rs`):

```
tr(NUMS, { and(pk(admin),older(144)), thresh(2,pk(A),pk(B),pk(C)) })
```

The descriptor is **directly importable** into standard Bitcoin wallets
(Sparrow, Liana, Nunchuk) — no custom BINST software needed to sign
vault spends. See `MINISCRIPT.md` for the full architecture.

The compiled script tree produces:

```
Taproot output:
  Internal key: NUMS point (unspendable — disables key-path spend)

  Script tree:
    Leaf 0 (admin transfer — time-delayed):
      <admin_pubkey> OP_CHECKSIG
      <144> OP_CHECKSEQUENCEVERIFY OP_DROP     ← ~24h delay (144 blocks)

    Leaf 1 (committee override — immediate):
      <key_A> OP_CHECKSIGVERIFY
      <key_B> OP_CHECKSIGADD
      <key_C> OP_CHECKSIGADD
      <2> OP_NUMEQUAL
```

**How it works:**

| Path | Who | Delay | Purpose |
|---|---|---|---|
| Key path | Nobody | ∞ | Disabled (NUMS internal key). No wallet can accidentally spend via key path. |
| Leaf 0 | Admin (single key) | ~24 hours (144 blocks CSV) | Deliberate admin transfer. The delay gives time to abort if the key is compromised. |
| Leaf 1 | 2-of-3 committee | Immediate | Emergency override: recover from key loss, or move inscription in time-sensitive situations. |

**Why this works for BINST:**

- **No accidental spending** — the key path is dead. A regular wallet
  that tries to sign a standard transaction will fail because the
  internal key is unspendable. Only the script paths work.
- **Admin retains control** — Leaf 0 lets the admin deliberately move
  the inscription (e.g., to a new address, or for a re-inscription),
  but the CSV delay acts as a safety net.
- **Committee backstop** — Leaf 1 is the "break glass" path. If the
  admin key is lost or compromised, the 2-of-3 multi-sig can recover
  the inscription immediately.
- **Wallet-native** — the miniscript descriptor imports directly into
  BIP 379 wallets. Users sign vault spends with Sparrow, Liana, or
  Nunchuk — no custom BINST tooling required.
- **Standard Bitcoin** — this uses only Taproot features available today
  (BIP 341/342, OP_CHECKSIG, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIGADD).
  No OP_CTV or OP_CAT needed.
- **Ordinals-compatible** — the `ord` indexer tracks inscriptions by
  ordinal theory regardless of the spending script. A Taproot script
  tree does not interfere with inscription tracking.

**Future enhancement with covenants:** When OP_CTV or OP_CAT activates
on Bitcoin, the script can be upgraded to enforce that the inscription
UTXO can *only* be spent to a pre-defined set of addresses (e.g., back
to the admin's own vault). This would make it truly non-transferable
except via explicit covenant paths.

#### Spending from the vault (unlock flow)

The vault **locks** the inscription UTXO, but it does not make it
permanently frozen. The admin can deliberately unlock it whenever needed.
Here is exactly what happens for each path:

**Path A — Admin transfer (Leaf 0, ~24h delay):**

```
1. Admin decides to move the inscription (e.g., to a new vault,
   to transfer ownership, or to perform a reinscription).

2. Admin waits until the UTXO is at least 144 blocks old
   (relative lock-time from when the UTXO was created/last spent).

3. Admin constructs a Bitcoin transaction:
   - Input: the vault UTXO
     - nSequence = 144 (satisfies OP_CHECKSEQUENCEVERIFY)
     - Witness: <admin_signature> <leaf_0_script> <control_block>
       where control_block = internal_key ‖ merkle_proof_to_leaf_0
   - Output 0: new destination address (e.g., a fresh vault for the same
     admin, or a new owner's vault address)
   - Output 1: change (if any)

4. Bitcoin consensus validates:
   a) admin_signature is valid for admin_pubkey    → OP_CHECKSIG ✓
   b) nSequence ≥ 144 blocks have passed           → OP_CSV ✓
   c) Taproot script-path commitment is correct     → control_block ✓

5. Transaction confirms. The inscription sat moves to the new output.
   The ord indexer updates the ownership record.
```

**Path B — Committee override (Leaf 1, immediate):**

```
1. Emergency: admin key is lost/compromised, or the institution
   needs to move the inscription urgently.

2. Two of three committee members agree and co-sign.

3. Committee constructs a Bitcoin transaction:
   - Input: the vault UTXO
     - nSequence = 0 (no CSV required on this leaf)
     - Witness: <0x00> <sig_A> <sig_B> <leaf_1_script> <control_block>
       where control_block = internal_key ‖ merkle_proof_to_leaf_1
   - Output 0: recovery destination

4. Bitcoin consensus validates:
   a) 2-of-3 multisig is satisfied                → OP_CHECKMULTISIG ✓
   b) Taproot script-path commitment is correct    → control_block ✓

5. Transaction confirms immediately (no waiting period).
```

**Re-locking after a spend:**

When the inscription moves out of the vault, the admin should send it
to a **new vault address** (generated with the same or updated keys)
to maintain the script-guard protection. The cycle is:

```
  Vault A  ──(admin spends after CSV)──▶  Vault B  ──(...)──▶  Vault C
    │                                        │
    └── inscription sat protected             └── re-locked, CSV resets
```

Each vault-to-vault transfer **resets the CSV timer** — the 144-block
countdown starts fresh from the block where Vault B's UTXO is confirmed.

**When would the admin unlock?**

| Scenario | Which path | What happens next |
|---|---|---|
| Transfer institution to new admin | Leaf 0 (admin) | Send to new admin's vault; update Citrea `transferAdmin()` |
| Rotate admin key | Leaf 0 (admin) | Send to vault with new admin pubkey |
| Reinscribe (update metadata) | Leaf 0 (admin) | Spend → new reveal TX → re-vault |
| Admin key compromised | Leaf 1 (committee) | Committee moves to safe address; admin rotates keys |
| Admin key lost | Leaf 1 (committee) | Committee recovers to new admin's vault |
| Move to covenant-upgraded vault | Leaf 0 (admin) | Migrate to OP_CTV vault when available |

**What if the admin never needs to unlock?**

That's fine — the inscription sits in the vault indefinitely. The sat is
safe, the inscription data is permanent, and the Citrea contract keeps
running. The vault is a safety net, not a requirement for normal operations.

#### Sat isolation (dedicated UTXO)

The inscribed satoshi should live on its own **dedicated, minimal UTXO**
— separate from any spending funds. This is standard Ordinals practice
and the `ord` tooling does it by default.

During the reveal transaction, two outputs are created:

```
Reveal TX:
  Input 0:  commit UTXO (inscription envelope in witness)

  Output 0: 546 sats → Taproot vault address (script-guarded)
             ↑ the inscribed sat lives HERE, alone
             ├── NUMS internal key (no key-path spend)
             ├── Leaf 0: admin + 144-block CSV delay
             └── Leaf 1: 2-of-3 committee multisig

  Output 1: change → admin's regular spending wallet
             Normal sats, freely spendable, no inscription.
```

The **pointer tag** (Ordinals tag 2) in the envelope explicitly binds
the inscription to the first satoshi of output 0. This guarantees:

- The inscribed sat is **physically isolated** — 546 sats (dust limit),
  containing nothing of spending value
- Change sats go to a **separate output** on a regular address
- No economic incentive to sweep the inscription UTXO
- Combined with the Taproot vault script: the isolated UTXO is also
  **consensus-locked** against accidental spends

This gives two independent layers of protection:
1. **Economic** — dust-limit UTXO has no spending value to attract
2. **Consensus** — script guard prevents spending even if attempted

#### Additional mitigations

| Layer | Mitigation | Effect |
|---|---|---|
| Wallet discipline | Use only Ordinals-aware wallets (Xverse, Unisat, `ord wallet`) | Inscription UTXOs are frozen and cannot be accidentally spent |
| Key isolation | Dedicated key/address for inscription UTXOs only | No mixing with spending funds eliminates accidental inclusion |
| Protocol design | Inscription UTXO = canonical ownership; L2 contract = delegate | Losing the L2 is recoverable; losing the key is the critical risk |
| Recovery path | Re-inscribe as child of original + deploy new L2 contract | Admin can recover from UTXO loss, but it is the hardest recovery |

#### Graceful degradation

**The critical design principle:** the Bitcoin key is the root of authority.
The inscription UTXO is the canonical proof of ownership. L2 contracts are
processing delegates that execute logic on behalf of the key holder.

The degradation hierarchy is:

**Losing the L2 contract (graceful):** If Citrea goes down, or the user
wants to switch to a different L2:

1. The inscription **data** is permanent and readable on Bitcoin forever
2. Membership Runes **continue to function** on Bitcoin L1
3. The admin **deploys a new contract** on another L2 (Stacks, BOB, etc.)
4. The new contract references the **same inscription ID** and rune ID
5. The institution continues with full identity and membership intact

This is the graceful case — the institution survives because the identity
lives on Bitcoin, not on any particular L2.

**Losing the inscription UTXO (serious):** If the admin accidentally spends
the inscription UTXO despite the vault protection:

1. The inscription **data** is permanent and readable forever
2. L2 contracts **continue to function** in the short term
3. The admin **re-inscribes** a recovery record (child of the original)
4. L2 contracts are **updated** to reference the new inscription
5. The original inscription's provenance chain is **preserved**

This is the serious case — the institution can recover, but it requires
a re-inscription and L2 contract update. The vault script guard exists
specifically to make this scenario extremely unlikely.

**Losing the Bitcoin private key (catastrophic):** If the admin loses
their Bitcoin private key:

1. The committee (Leaf 1, 2-of-3 multisig) can **recover the inscription**
   to a new key's vault address
2. The admin **deploys new L2 contracts** from the new key
3. This is the catastrophic case — recovery requires the committee and
   is the reason the multi-sig backstop exists

**The hierarchy:**

```
L2 contract lost     → redeploy elsewhere, identity survives on Bitcoin
Inscription UTXO lost → re-inscribe + update L2 (harder, but recoverable)
Bitcoin key lost      → committee recovery (hardest, requires multi-sig)
```

### Discovery

BINST inscriptions are discoverable through standard tooling:
- Ordinals explorers (ordinals.com, ord.io, Hiro) — search by metaprotocol
- Ordinals wallets (Xverse, Unisat) — shows as an asset
- Self-hosted `ord` indexer — trustless, complete access
- **No custom BINST software needed for basic discovery**

---

## Runes — membership tokens

Each institution etches a **Rune** that represents membership.

```
Rune: ACME•MEMBER
  Divisibility: 0  (whole units only — member or not)
  Symbol: 🏛
  Premine: 1  (admin gets the first unit)
  Terms: cap=1000, amount=1 (admin mints and distributes)
```

### How membership works

- **Check:** "Is Alice a member?" → "Does Alice hold ≥1 `ACME•MEMBER`?"
  Standard Rune indexer query. No Citrea needed.
- **Add:** Admin sends 1 unit to new member's Bitcoin address.
- **Remove:** Admin burns the token via edict, or member sends it back.
- **Visible:** Members see membership in any Rune-aware wallet.

This mirrors the Solidity `addMember`/`removeMember` pattern but lives
entirely on Bitcoin L1.

### Future: governance tokens

A separate Rune (e.g., `ACME•VOTE`) with divisibility could represent
weighted voting power. Governance becomes a token distribution problem.

---

## L2 processing layer (currently Citrea)

Complex institutional logic executes on L2 smart contracts **as a delegate
of the Bitcoin key holder**:
- Multi-step workflow execution with validation rules
- Payment processing
- Cross-contract calls and event emission
- State management (current step, completion, timestamps)

The L2 is a processing engine — it does not own the identity. The user
can redeploy to a different L2 at any time, pointing the new contracts
at the same inscription ID. The identity stays on Bitcoin.

**L2 portability:** because the root of authority is the Bitcoin key (not
the L2 contract address), the protocol is not locked into any specific L2.
A user who starts on Citrea can later move to Stacks, BOB, or any future
Bitcoin L2 without losing their institution's identity, provenance, or
membership.

The current L2 (Citrea) periodically writes **ZK batch proofs** to Bitcoin —
mathematical guarantees that every state transition was computed correctly.
Other L2s may use different proof mechanisms (optimistic, validity, etc.)
but the Bitcoin-layer identity is unchanged regardless.

See `DECODING.md` for the technical format of batch proofs and
sequencer commitments.

---

## Architecture diagram

```
┌─────────────────────────────────────────────────────────────┐
│               BITCOIN (L1) — ROOT OF AUTHORITY               │
│                                                             │
│  ┌───────────────────────┐    ┌──────────────────────────┐  │
│  │   ORDINAL INSCRIPTIONS │    │        RUNES             │  │
│  │   (Identity Layer)     │    │   (Membership Layer)     │  │
│  │   ★ AUTHORITATIVE ★   │    │                          │  │
│  │                        │    │  ACME•MEMBER (fungible)  │  │
│  │  Root: "binst" proto   │    │  BCU•MEMBER              │  │
│  │   └─ Institution       │    │  ACME•VOTE (governance)  │  │
│  │       └─ Template      │    │                          │  │
│  │           └─ Instance  │    │                          │  │
│  │               └─ Event │    │                          │  │
│  │                        │    │  Membership = balance    │  │
│  │  Ownership = UTXO      │    │  Discoverable in         │  │
│  │  controlled by BTC key │    │  any Rune indexer        │  │
│  │  ← THIS is the admin   │    │                          │  │
│  └───────────────────────┘    └──────────────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              L2 BATCH PROOFS                          │   │
│  │   (ZK-proven state diffs — computational integrity)   │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            │
                            │ L2 writes proofs to Bitcoin
                            │
┌─────────────────────────────────────────────────────────────┐
│              L2 PROCESSING LAYER (delegate)                  │
│           Currently: Citrea  |  Portable to any L2           │
│                                                             │
│  Institution.sol    ProcessTemplate.sol    ProcessInstance.sol│
│  BINSTDeployer.sol                                          │
│                                                             │
│  Executes logic ON BEHALF OF the Bitcoin key holder:        │
│  - Step execution with validation                           │
│  - Payment processing                                       │
│  - Complex multi-step workflows                             │
│  - Event emission and indexing                              │
│  - Cross-contract calls                                     │
│                                                             │
│  L2 contract is BOUND TO inscription ID:                    │
│  - inscriptionId → links to Bitcoin identity                │
│  - runeId → links to Bitcoin membership                     │
│  - admin → derived from / authorized by Bitcoin key         │
│                                                             │
│  User can redeploy to another L2 at any time.               │
│  The inscription stays. The identity stays. Only the         │
│  processing layer changes.                                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Institution anchoring lifecycle

An institution progresses through three anchoring states:

```
State 1: UNANCHORED (L2-only)
  → Contract deployed on Citrea (or any L2)
  → Functional on L2: members, processes work
  → Batch proofs reach Bitcoin DA (orphan proofs — see below)
  → No inscription, no rune
  → Status: DRAFT

State 2: BINDING (partially anchored)
  → Contract deployed + inscription created
  → But not yet fully linked (setInscriptionId not called,
    or rune not yet etched)
  → Status: BINDING

State 3: ANCHORED (fully sovereign)
  → Contract deployed + inscription bound + rune etched + rune bound
  → L2 state is provably linked to Bitcoin identity
  → Status: ANCHORED
```

**Anchoring is not deployment.** An institution exists on the L2 from
the moment its contract is deployed. It becomes *Bitcoin-anchored* when
its Ordinals inscription is created and bound to the contract. Unanchored
institutions are functional but not verifiable from Bitcoin L1.

### Orphan ZK proofs

If a user deploys `Institution.sol` on Citrea but never inscribes the
ordinal identity, the ZK batch proof still reaches Bitcoin DA. This is
an **orphan proof** — valid (it proves the L2 state transition happened)
but unanchored (no Bitcoin-native identity to attach it to).

The `binst-decoder` would see storage slot changes for an Institution
contract, but `inscriptionId` and `runeId` would be empty strings.

Orphan proofs are **not harmful** — they are noise the indexer filters
with a simple check: `if inscriptionId == "" → skip`. This is by design:

- Lowers the barrier to entry — users can experiment on L2 for just gas
- Creates a natural funnel: experiment → anchor → grow
- Citrea batches state regardless; you cannot prevent orphan proofs
  without gatekeeping contract deployment

---

## Read/write phase model

### Write phases (user-initiated transactions)

```
┌──────────────┬──────────────────┬───────────────────────┐
│ Action       │ Where            │ Who pays / signs      │
├──────────────┼──────────────────┼───────────────────────┤
│ Inscribe ID  │ Bitcoin (ordinal)│ User, BTC wallet      │
│ Mint Rune    │ Bitcoin (rune)   │ User, BTC wallet      │
│ Deploy Inst. │ Citrea (EVM)     │ User, EVM wallet      │
│ Bind IDs     │ Citrea (EVM)     │ User, EVM wallet      │
│ Add Member   │ Citrea (EVM)     │ Admin, EVM wallet     │
│ Send Rune    │ Bitcoin (rune)   │ Admin, BTC wallet     │
│ Create Proc  │ Citrea (EVM)     │ Admin, EVM wallet     │
│ Execute Step │ Citrea (EVM)     │ Member, EVM wallet    │
└──────────────┴──────────────────┴───────────────────────┘
```

### Automatic (no user action)

```
┌──────────────┬──────────────────┬───────────────────────┐
│ Batch proof  │ Bitcoin DA       │ Citrea sequencer      │
│ (ZK rollup)  │                  │ (periodic, async)     │
└──────────────┴──────────────────┴───────────────────────┘
```

### Read phases (free, no transaction)

```
┌──────────────┬──────────────────┬───────────────────────┐
│ Verify member│ Citrea (EVM)     │ Free (view call)      │
│ Check process│ Citrea (EVM)     │ Free (view call)      │
│ Verify inscr.│ Bitcoin (ord)    │ Free (indexer query)  │
│ Verify proof │ Bitcoin DA       │ Free (decode batch)   │
│ Cross-chain  │ LayerZero/DA     │ Relay fee or free     │
└──────────────┴──────────────────┴───────────────────────┘
```

**Key insight:** the user does NOT create a Bitcoin transaction when they
deploy on Citrea. Citrea's batch proof reaches Bitcoin automatically,
asynchronously — the user doesn't trigger it or pay for it. It's the
sequencer's job. The inscription (ordinal) is a separate, deliberate
Bitcoin transaction that the user initiates to create the identity anchor.

### Wallet UX (current vs future)

**Today (Phase 1-3):** Two wallets. Bitcoin wallet (Xverse, Unisat) for
inscriptions and runes. EVM wallet (MetaMask) for L2 transactions. The
Schnorr precompile on Citrea (`0x5a`) means contracts *can verify* Bitcoin
signatures, but the webapp flow requires both wallets.

**Future (Phase 4+):** Single Bitcoin wallet. Account abstraction or
Schnorr-verified sessions allow the user to sign once with their Bitcoin
key, and an AA layer submits to the L2. One wallet, one identity.

### Entity creation vs event registration

| Pattern | Bitcoin TX needed? | Example |
|---|---|---|
| **Entity creation** | Yes (inscription/rune) + L2 tx | Create institution, etch rune |
| **Event registration** | L2 tx only (batch proof automatic) | Execute step, add member |
| **Verification** | No (read only) | Check membership, verify proof |

---

## Protocol flows

### Creating an institution

```
1. Admin generates a Bitcoin key pair (x-only Taproot pubkey)
   → this key IS the institution's identity root
   → everything else derives from this key

2. Admin inscribes institution on Bitcoin (Ordinal)
   → metaprotocol: "binst", body: institution metadata
   → gets inscription ID: abc123...i0
   → inscription lives in a Taproot vault UTXO → admin owns it
   → the inscription is the institution's birth certificate

3. Admin etches membership Rune on Bitcoin
   → INSTITUTION•MEMBER, premine: 1
   → admin holds the initial unit

4. Admin deploys Institution.sol on an L2 (currently Citrea)
   → constructor gets: name, admin address
   → admin calls setInscriptionId() and setRuneId() to bind the contract
   → the L2 contract is now a DELEGATE of the Bitcoin key holder

5. L2 state reaches Bitcoin via batch proof
   → institution is now represented THREE ways on Bitcoin:
      a) Ordinal inscription (identity — AUTHORITATIVE)
      b) Rune (membership token)
      c) State diff in batch proof (computational state)
```

Note: step 4 can be repeated on any L2. The inscription ID and Rune ID
stay the same. Only the L2 contract address changes.

Note: steps 2-3 (Bitcoin) and step 4 (L2) are independent — they can
happen in any order. If step 4 happens first without steps 2-3, the
institution is UNANCHORED (see "Institution anchoring lifecycle" above).

### Switching L2s

```
1. Admin decides to move from Citrea to another L2 (e.g., Stacks)

2. Admin deploys new Institution contract on the new L2
   → binds it to the SAME inscription ID and rune ID

3. The Bitcoin-layer identity is unchanged:
   → same inscription, same UTXO, same admin key
   → same membership Rune, same member balances
   → provenance chain is intact

4. The old L2 contract becomes historical — its batch proofs
   remain on Bitcoin as a permanent record of past operations

5. New operations flow through the new L2 contract
   → the institution continues seamlessly
```

### Cross-chain state synchronization

BINST institutions can be **omnipresent across multiple L2s** simultaneously,
not just portable between them. This uses a dual-channel sync model:

```
Bitcoin (inscription + rune) = AUTHORITY
    ↓
Home L2 (e.g., Citrea) = PRIMARY DELEGATE (read + write)
    ↓ LayerZero V2 (identity)     ↓ Bitcoin DA (execution proof)
Mirror L2s (BOB, Rootstock, etc.) = READ-ONLY MIRRORS
```

**Two sync channels, each for what it's good at:**

| Channel | What it syncs | Speed | Trust model |
|---|---|---|---|
| **LayerZero V2** | Identity: name, admin, members, inscriptionId, runeId | Fast (real-time) | DVN-configurable |
| **Bitcoin DA** | Execution: process step states, completion proofs | Slow (batch interval) | Trustless (ZK-proven) |

LayerZero V2 has deployed endpoints on Citrea mainnet (Chain ID 4114,
Endpoint ID 30403) and 8+ Bitcoin L2s (BOB, Bitlayer, BEVM, Merlin,
Rootstock, Hemi, Corn, Goat).

**The three state tiers:**

| Tier | Data | Sync method | Writable? |
|---|---|---|---|
| **Identity** | inscriptionId, runeId, admin, name | LayerZero (fast) | Home chain only |
| **Membership** | members[], isMember | LayerZero (fast) | Home chain only |
| **Execution** | stepStates[], process progress | Bitcoin DA (trustless) | Home chain only |

**Critical rule: single-writer per ProcessInstance.** A ProcessInstance
lives on exactly one home chain. It is created there, executed there,
completed there. Mirror chains can *read* process state (via Bitcoin DA
batch proofs) but cannot *mutate* it. This prevents concurrent execution
conflicts — two L2s cannot execute the same step simultaneously because
only the home chain has write access.

Mirror contracts (`InstitutionMirror.sol`) expose read-only functions:
`isMember()`, `getAdmin()`, `getInscriptionId()` — no `executeStep()`,
no `createProcess()`. The type system enforces the invariant.

**Cross-chain process references:** If a process on BOB needs to verify
a step completed on Citrea (e.g., "KYC must be done before this audit"),
it performs a cross-chain read — querying the Citrea mirror or verifying
the step state from Bitcoin DA. No mutation, no conflict.

**Trust considerations:** LayerZero introduces a dependency outside Bitcoin
(messages go through DVNs, not Bitcoin DA). This is acceptable because:
- The **authority** remains on Bitcoin (inscription UTXO)
- Mirrors are **convenience, not consensus** — any L2 can independently
  verify the inscription on Bitcoin
- If LayerZero goes down, institutions still function on their home L2

### Adding a member

```
1. Admin sends 1 INSTITUTION•MEMBER rune to new member's address
   → member now holds membership token in their Bitcoin wallet
   → visible in any Rune-aware wallet or indexer

2. Admin calls addMember(memberAddress) on the L2 contract
   → L2 contract updates member list
   → (optional: contract verifies Rune balance via bridge)

3. L2 state diff reaches Bitcoin via batch proof
   → member addition is now ZK-proven on Bitcoin
```

### Executing a process step

```
1. Member calls executeStep() on L2 ProcessInstance
   → complex validation, payment, state transitions happen on L2
   → event emitted: StepExecuted(who, stepIndex, timestamp)

2. (Optional) Member inscribes step execution as child of instance
   → permanent, discoverable record on Bitcoin
   → not required for protocol correctness (batch proof handles that)
   → makes it human-readable on explorers

3. L2 batch proof writes state diff to Bitcoin
   → step execution is ZK-proven
```

### Transferring admin (ownership transfer)

```
1. Current admin transfers the inscription UTXO to new admin's vault
   → on Bitcoin: new admin now controls the UTXO (Leaf 0 spend)
   → the inscription ID stays the same; the controlling key changes

2. New admin calls transferAdmin() on the L2 contract
   → L2 contract updates admin address to match new key holder

3. Both layers now agree: the new admin controls the institution
   on Bitcoin (UTXO) and on the L2 (contract state)

Note: if the L2 contract admin disagrees with the UTXO owner,
the UTXO owner is authoritative. The L2 contract is expected to
be updated to match. A future version could enforce this via
a Bitcoin-key-based signature verification on the L2.
```

---

## What each layer guarantees

| Layer | What it proves | Trust assumption | Discoverability | Failure mode |
|---|---|---|---|---|
| **Ordinal inscription** | Entity exists, metadata is set, **admin controls UTXO** | Bitcoin consensus | Any Ordinals explorer/wallet | UTXO accidentally spent → lose root authority (serious — vault prevents this) |
| **Rune balance** | This person is a member | Bitcoin consensus | Any Rune indexer/wallet | Token accidentally sent → membership lost until re-minted |
| **L2 contract** | Processing delegate: executes logic on behalf of BTC key | Bitcoin consensus + ZK math | L2 RPC | L2 down → redeploy on another L2, identity survives on Bitcoin |
| **L2 batch proof** | Every state transition was computationally correct | Bitcoin consensus + ZK math | taproot-reader + full node | Proof missing → state unverifiable until next batch |

**The Bitcoin key is the single root of authority.** L2 contracts are
replaceable processing delegates. Losing an L2 is graceful — redeploy
elsewhere. Losing the Bitcoin key is catastrophic — the committee multi-sig
is the last resort.

---

## Entity-to-primitive mapping

| Entity | Nature | Bitcoin primitive | Reasoning |
|---|---|---|---|
| **Institution** | Unique, one-of-one | Ordinal inscription | Needs metadata, provenance, UTXO-based ownership |
| **Process Template** | Unique, immutable | Ordinal inscription (child of institution) | Unique artifact with structured content |
| **Process Instance** | Unique, mutable state | Ordinal inscription (child of template) | State updates via child inscriptions or batch proofs |
| **Membership** | Fungible relationship | Rune balance | "Hold ≥1 token = member" is a standard balance check |
| **Step Execution** | Immutable event record | Ordinal inscription (child of instance) | Permanent discoverable record |
| **Governance vote** | Fungible weight | Rune balance (separate per institution) | Transferable, weighted voting power |

---

## The `BitcoinIdentity` type

Every BINST entity in the decoder carries a `BitcoinIdentity` struct
linking it across all reachability layers:

```rust
pub struct BitcoinIdentity {
    /// Taproot x-only public key (32 bytes) — ROOT OF AUTHORITY.
    /// This key controls the inscription UTXO and is the canonical
    /// identity of the entity. All other fields derive from or
    /// reference this key.
    pub bitcoin_pubkey: [u8; 32],

    /// Ordinals inscription ID (e.g., "abc123...i0")
    pub inscription_id: Option<String>,

    /// Rune ID for membership token (e.g., "840000:20")
    pub membership_rune_id: Option<String>,

    /// EVM address on the current L2 (derived from or authorized by the BTC key)
    pub evm_address: Option<[u8; 20]>,

    /// HD derivation path hint (e.g., "m/86'/0'/0'/0/0")
    pub derivation_hint: Option<String>,
}
```

The ordering reflects the authority hierarchy:
1. `bitcoin_pubkey` — the root of authority (controls the inscription UTXO)
2. `inscription_id` — the entity's permanent identity on Bitcoin
3. `membership_rune_id` — membership token on Bitcoin
4. `evm_address` — the current L2 processing delegate (can change if L2 changes)

---

## Discovery: who needs what

| What you want to know | Where to look | Full node needed? |
|---|---|---|
| Does institution X exist? | Ordinals explorer | ❌ No |
| Who is the admin? | Inscription UTXO owner (Bitcoin key) | ❌ No |
| Am I a member? | Rune balance in wallet | ❌ No |
| Who are all members? | Rune indexer query | ❌ No |
| What processes exist? | Child inscriptions | ❌ No |
| What step is instance Y on? | L2 RPC (currently Citrea) | ❌ No |
| Is institution X anchored? | L2 view call (inscriptionId != "") | ❌ No |
| Was step execution valid? | ZK batch proof decode | ✅ Yes |
| Full trustless verification? | taproot-reader | ✅ Yes |
| Which L2 is currently processing? | Inscription metadata or re-inscription | ❌ No |
| Is this person a member? (cross-chain) | InstitutionMirror on any L2 | ❌ No |
| Did step X complete? (cross-chain) | Bitcoin DA batch proof decode | ✅ Yes |

**Basic discovery requires no custom software and no full node.** Standard
Ordinals and Rune tooling covers identity, ownership, membership, and
provenance. The full node is only needed for the strongest verification
tier — independently confirming ZK proofs. And critically: none of this
depends on any specific L2 being online.

---

## Cost analysis

| Operation | Mechanism | Approx. cost (at 10 sat/vB) |
|---|---|---|
| Create institution | Ordinal inscription (~500B text) | ~$2-5 |
| Create process template | Child inscription (~300B) | ~$1-3 |
| Record step execution | Child inscription (~200B) | ~$0.50-2 |
| Etch membership Rune | Runestone in OP_RETURN | ~$1-3 |
| Mint membership for 1 user | Runestone transaction | ~$0.50-1 |
| Transfer institution admin | Send UTXO (standard tx) | ~$0.30-1 |
| **Total: institution + template + 10 members** | | **~$15-30** |

Testnet4 is free during development. Mainnet costs scale with fee rates
but remain reasonable for institutional operations that happen infrequently.

---

## Implementation phases

### Phase 1: Inscription identity ✅
- Define the `binst` metaprotocol JSON schema (institution/template/instance)
- Script to inscribe an institution on Bitcoin testnet4 using `ord`
- **Build Taproot vault script** for inscription UTXOs (NUMS internal key,
  admin CSV-delayed path, 2-of-3 committee override path)
- Add `inscription_id` field to Solidity contracts
- Update taproot-reader to find `binst` metaprotocol inscriptions
- Update `BitcoinIdentity` struct with `inscription_id`

### Phase 2: Bitcoin-key sovereignty 🔧 (in progress)
- ✅ Refactor `BitcoinIdentity` struct: `bitcoin_pubkey` becomes required (root),
  `evm_address` becomes optional (L2 delegate reference)
- ⬜ Add `btcPubkey` field to `Institution.sol` — the L2 contract stores the
  Bitcoin key it is bound to, making the delegation explicit
- ⬜ Explore BTC key → EVM address derivation for trustless binding
- ✅ Document L2 portability: how to migrate from one L2 to another while
  keeping the same inscription and Rune identity

### Phase 3: Membership Runes & Cross-Chain Sync
- Etch a test Rune per institution on testnet4
- Add `rune_id` field to Institution.sol
- Script to mint and distribute membership Runes
- Update `BitcoinIdentity` struct with `membership_rune_id`
- Explore Clementine bridge for Rune balance verification on L2
- **Cross-chain sync via LayerZero V2** (Citrea endpoint live: chain 4114,
  endpoint ID 30403): `BINSTRelay.sol` OApp broadcasts identity/membership
  state to mirror chains; `InstitutionMirror.sol` provides read-only
  verification on other L2s (BOB, Rootstock, etc.)
- Batch Bitcoin-side operations (inscribe + etch in fewer transactions)

### Phase 4: Bitcoin-native discovery
- Indexer that watches for `binst` metaprotocol inscriptions
- API: "list all BINST institutions" → Ordinals query for `metaprotocol=binst`
- API: "list members of institution X" → Rune balance query for `X•MEMBER`
- API: "verify institution state" → cross-reference inscription, Rune, batch proof
- Cross-chain process state verification via Bitcoin DA batch proof reads
- Single-wallet UX: Schnorr-verified sessions via account abstraction

### Phase 5: Deep Bitcoin integration
- **Covenant-upgraded vault** (when OP_CTV/OP_CAT activates): inscription
  UTXO can only be spent to pre-approved addresses
- Multi-sig institution admin via Taproot MuSig2
- Cross-institution process verification using inscription provenance chains
- Rune-gated access control (hold ≥1 `X•MEMBER` to interact)
- BTC key signature verification on L2 (trustless delegation proof)
- BitVM verification of cross-chain state consistency

---

## Related documents

- `conceptual.md` — non-technical overview of the three-layer architecture
- `DECODING.md` — technical reference for Citrea DA transaction decoding
- `crates/binst-decoder/src/entities.rs` — `BitcoinIdentity` struct implementation
- `crates/binst-decoder/src/storage.rs` — Solidity storage slot computation
