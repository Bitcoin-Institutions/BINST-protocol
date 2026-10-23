#!/usr/bin/env bash
# ─── BINST Protocol — End-to-End Demo ────────────────────────────
# Demonstrates the full BINST lifecycle:
#   1. Inscribe an Institution on Bitcoin L1 (via binst inscribe)
#   2. Inscribe a ProcessTemplate as a child of that Institution
#   3. Deploy a BINSTProcess instance on Citrea L2 (via cast)
#   4. Execute each step on L2
#   5. Verify Bitcoin settlement finality
#
# ── Prerequisites ─────────────────────────────────────────────────
#   - binst CLI (cargo build --bin binst in this repo)
#   - cast      (https://getfoundry.sh)
#   - curl, jq, python3
#   - A Bitcoin testnet4 private key with funded address
#   - A Citrea testnet private key with cBTC (wizard generates one)
#
# ── Usage ─────────────────────────────────────────────────────────
#   chmod +x demo.sh
#   ./demo.sh              # interactive wizard
#   ./demo.sh --l2-only    # skip Bitcoin inscriptions, use example IDs
#
# ── Networks ──────────────────────────────────────────────────────
#   Bitcoin: Testnet4  (mempool.space/testnet4)
#   Citrea:  Testnet   (chain 5115, rpc.testnet.citrea.xyz)
# ──────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

banner() { echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"; echo -e "${BLUE}║${NC}  ${BOLD}$1${NC}"; echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}\n"; }
step()   { echo -e "${CYAN}▸${NC} ${BOLD}$1${NC}"; }
ok()     { echo -e "  ${GREEN}✓${NC} $1"; }
warn()   { echo -e "  ${YELLOW}⚠${NC} $1"; }
fail()   { echo -e "  ${RED}✗${NC} $1"; exit 1; }
info()   { echo -e "  ${BLUE}ℹ${NC} $1"; }

# ── Constants ─────────────────────────────────────────────────────
CITREA_RPC="https://rpc.testnet.citrea.xyz"
CITREA_CHAIN_ID=5115
FACTORY_ADDRESS="0x6a1d2adbac8682773ed6700d2118c709c8ce5000"
MEMPOOL_API="https://mempool.space/testnet4/api"
DEMO_DIR="$(mktemp -d)/binst-demo"
mkdir -p "$DEMO_DIR"

L2_ONLY=false
[[ "${1:-}" == "--l2-only" ]] && L2_ONLY=true

# ── Cleanup ───────────────────────────────────────────────────────
cleanup() { rm -rf "$DEMO_DIR"; }
trap cleanup EXIT

banner "BINST Protocol — End-to-End Demo"
echo "  This script demonstrates the full BINST lifecycle:"
echo "    L1: Inscribe Institution → ProcessTemplate (Bitcoin testnet4)"
echo "    L2: Deploy Instance → Execute Steps (Citrea testnet)"
echo "    Settlement: Verify Bitcoin finality tiers"
echo ""
if $L2_ONLY; then
  warn "Running in L2-only mode (--l2-only). Bitcoin inscriptions will be skipped."
  echo ""
fi

# ══════════════════════════════════════════════════════════════════
# SECTION 1: Dependency Checks
# ══════════════════════════════════════════════════════════════════

banner "1 · Checking Dependencies"

check_cmd() {
  if command -v "$1" &>/dev/null; then
    ok "$1 found ($(command -v "$1"))"
  else
    fail "$1 not found. $2"
  fi
}

check_cmd curl   "Install: brew install curl"
check_cmd jq     "Install: brew install jq"
check_cmd python3 "Install: brew install python3"
check_cmd cast   "Install: curl -L https://foundry.paradigm.xyz | bash && foundryup"

if ! $L2_ONLY; then
  if command -v binst &>/dev/null; then
    ok "binst found ($(command -v binst))"
  else
    step "Building binst CLI from source..."
    cargo build --bin binst --release -q 2>/dev/null && ok "binst built" || fail "Failed to build binst. Run: cargo build --bin binst"
  fi
fi

# Verify Citrea RPC is reachable
step "Testing Citrea RPC..."
CITREA_BLOCK=$(curl -sf -X POST "$CITREA_RPC" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  | jq -r '.result' | python3 -c "import sys; print(int(sys.stdin.read().strip(),16))")
ok "Citrea testnet reachable — block $CITREA_BLOCK"

# ══════════════════════════════════════════════════════════════════
# SECTION 2: Wallet Configuration Wizard
# ══════════════════════════════════════════════════════════════════

banner "2 · Wallet Configuration"

# ── L2 (Citrea) wallet ────────────────────────────────────────────
step "Citrea wallet setup"

if [[ -n "${CITREA_PRIVATE_KEY:-}" ]]; then
  info "Using CITREA_PRIVATE_KEY from environment"
else
  echo ""
  echo "  You need a Citrea testnet private key with cBTC for gas."
  echo "  Options:"
  echo "    1) Enter an existing private key"
  echo "    2) Generate a fresh throwaway key (you'll need to fund it)"
  echo ""
  read -rp "  Choice [1/2]: " L2_CHOICE
  if [[ "$L2_CHOICE" == "2" ]]; then
    CITREA_PRIVATE_KEY=$(cast wallet new | grep "Private key:" | awk '{print $3}')
    CITREA_ADDRESS=$(cast wallet address "$CITREA_PRIVATE_KEY")
    warn "Generated fresh wallet: $CITREA_ADDRESS"
    warn "Fund it with cBTC from the Citrea testnet faucet before proceeding."
    echo "  Faucet: https://faucet.testnet.citrea.xyz"
    read -rp "  Press Enter when funded..." _
  else
    read -rsp "  Enter Citrea private key (0x...): " CITREA_PRIVATE_KEY
    echo ""
  fi
fi

CITREA_ADDRESS=$(cast wallet address "$CITREA_PRIVATE_KEY")
CITREA_BALANCE=$(cast balance "$CITREA_ADDRESS" --rpc-url "$CITREA_RPC" 2>/dev/null || echo "0")
ok "Citrea address: $CITREA_ADDRESS"
ok "Balance: $CITREA_BALANCE"

# ── L1 (Bitcoin) wallet — only if full mode ───────────────────────
INSTITUTION_ID=""
TEMPLATE_ID=""
INST_REVEAL=""
TMPL_REVEAL=""

if ! $L2_ONLY; then
  step "Bitcoin wallet setup"
  echo ""
  echo "  BINST uses its own inscription pipeline (no ord CLI or Bitcoin"
  echo "  Core needed). Just a private key and a funded testnet4 address."
  echo ""
  echo "  Options:"
  echo "    1) Enter an existing private key (WIF or hex)"
  echo "    2) Skip L1 inscriptions → continue in L2-only mode"
  echo ""
  read -rp "  Choice [1/2]: " BTC_CHOICE
  if [[ "$BTC_CHOICE" == "2" ]]; then
    warn "Skipping Bitcoin L1 inscriptions."
    L2_ONLY=true
  else
    read -rsp "  Enter Bitcoin testnet4 private key: " BTC_PRIVATE_KEY
    echo ""
    # Derive address via binst vault (just needs the key to show the address)
    BTC_ADDRESS=$(cargo run --bin binst -q -- inscribe --file /dev/null --private-key "$BTC_PRIVATE_KEY" --network testnet4 2>&1 | grep "Address:" | awk '{print $2}' || echo "")
    if [[ -n "$BTC_ADDRESS" ]]; then
      ok "Bitcoin address: $BTC_ADDRESS"
    else
      info "Will derive address during inscription..."
    fi
  fi

  # ════════════════════════════════════════════════════════════════
  # SECTION 3: Inscribe Institution on Bitcoin L1
  # ════════════════════════════════════════════════════════════════

  if ! $L2_ONLY; then
    banner "3 · Inscribing Institution on Bitcoin L1"

    INST_BODY=$(cat << 'INST_JSON'
{
  "v": 0,
  "type": "institution",
  "name": "BINST Demo Institution",
  "admin": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "description": "Demo institution created by demo.sh"
}
INST_JSON
)
    echo "$INST_BODY" > "$DEMO_DIR/institution.json"
    ok "Institution body written"
    echo "$INST_BODY" | jq .

    step "Inscribing institution via binst inscribe (serverless — mempool.space API)..."
    INST_RESULT=$(cargo run --bin binst -q -- inscribe \
      --file "$DEMO_DIR/institution.json" \
      --private-key "$BTC_PRIVATE_KEY" \
      --network testnet4 \
      --format json 2>"$DEMO_DIR/inscribe-institution.log") || true

    INSTITUTION_ID=$(echo "$INST_RESULT" | jq -r '.inscription_id // empty' 2>/dev/null)
    INST_REVEAL=$(echo "$INST_RESULT" | jq -r '.reveal_txid // empty' 2>/dev/null)

    if [[ -z "$INSTITUTION_ID" ]]; then
      warn "Institution inscription failed. Output:"
      sed 's/^/  /' "$DEMO_DIR/inscribe-institution.log"
      warn "Falling back to L2-only mode."
      L2_ONLY=true
    else
      ok "Institution inscribed!"
      ok "  Inscription ID: $INSTITUTION_ID"
      ok "  Reveal tx:      $INST_REVEAL"
      ok "  Explorer:        $MEMPOOL_API/tx/$INST_REVEAL"

      # Wait for mempool propagation
      step "Waiting for mempool propagation (10s)..."
      sleep 10

      # ══════════════════════════════════════════════════════════════
      # SECTION 4: Inscribe ProcessTemplate as child of Institution
      # ══════════════════════════════════════════════════════════════

      banner "4 · Inscribing ProcessTemplate on Bitcoin L1"

      cat > "$DEMO_DIR/template.json" << TMPL_JSON
{
  "v": 0,
  "type": "process_template",
  "name": "Demo KYC Process",
  "institution_id": "$INSTITUTION_ID",
  "description": "3-step KYC workflow for demo purposes",
  "steps": [
    { "name": "Document Upload", "action_type": "upload" },
    { "name": "Identity Verification", "action_type": "verification" },
    { "name": "Final Approval", "action_type": "approval" }
  ]
}
TMPL_JSON
      ok "Template body written"
      jq . "$DEMO_DIR/template.json"

      # The CLI cannot spend the parent's sat yet, so this template is linked
      # to the institution only by `institution_id` in its body, not by ord
      # parent-child provenance. The webapp inscribes real children.
      step "Inscribing process template (linked by institution_id)..."
      TMPL_RESULT=$(cargo run --bin binst -q -- inscribe \
        --file "$DEMO_DIR/template.json" \
        --private-key "$BTC_PRIVATE_KEY" \
        --network testnet4 \
        --format json 2>"$DEMO_DIR/inscribe-template.log") || true

      TEMPLATE_ID=$(echo "$TMPL_RESULT" | jq -r '.inscription_id // empty' 2>/dev/null)
      TMPL_REVEAL=$(echo "$TMPL_RESULT" | jq -r '.reveal_txid // empty' 2>/dev/null)

      if [[ -z "$TEMPLATE_ID" ]]; then
        warn "Template inscription failed. Output:"
        sed 's/^/  /' "$DEMO_DIR/inscribe-template.log"
        warn "Falling back to L2-only mode with institution only."
      else
        ok "ProcessTemplate inscribed!"
        ok "  Inscription ID: $TEMPLATE_ID"
        ok "  institution_id: $INSTITUTION_ID (body field; no ord parent-child link)"
        ok "  Reveal tx:       $TMPL_REVEAL"
      fi
    fi
  fi

fi  # end of !L2_ONLY block

# ── L2-only fallback: use example inscription IDs ─────────────────
if $L2_ONLY || [[ -z "$TEMPLATE_ID" ]]; then
  banner "3-4 · Skipped (L2-only mode)"
  info "Using a REAL inscription from a prior testnet4 demo."
  info "The L2 contract stores the inscription ID as a string anchor."
  info "Anyone can verify it on Bitcoin: mempool.space/testnet4"
  echo ""
  INSTITUTION_ID="0280ede1b09ceb87cdd661adb4a317d80586abf1576d7d869bc1cd177bfa7243i0"
  TEMPLATE_ID="$INSTITUTION_ID"
  STEP_NAMES='["Document Upload","Identity Verification","Final Approval"]'
  STEP_TYPES='["upload","verification","approval"]'
  ok "Anchor inscription: $INSTITUTION_ID"
  ok "Verify on Bitcoin:  ${MEMPOOL_API}/tx/${INSTITUTION_ID%i*}"
fi

# Prepare step arrays for contract call
STEP_NAMES="${STEP_NAMES:-[\"Document Upload\",\"Identity Verification\",\"Final Approval\"]}"
STEP_TYPES="${STEP_TYPES:-[\"upload\",\"verification\",\"approval\"]}"

# ══════════════════════════════════════════════════════════════════
# SECTION 5: Deploy BINSTProcess Instance on Citrea L2
# ══════════════════════════════════════════════════════════════════

banner "5 · Creating Process Instance on Citrea L2"

step "Calling BINSTProcessFactory.createInstance()..."
info "Factory:  $FACTORY_ADDRESS"
info "Template: $TEMPLATE_ID"

CREATE_TX=$(cast send "$FACTORY_ADDRESS" \
  "createInstance(string,string[],string[])" \
  "$TEMPLATE_ID" \
  "$STEP_NAMES" \
  "$STEP_TYPES" \
  --rpc-url "$CITREA_RPC" \
  --private-key "$CITREA_PRIVATE_KEY" \
  --json 2>&1)

CREATE_TX_HASH=$(echo "$CREATE_TX" | jq -r '.transactionHash // empty')
if [[ -z "$CREATE_TX_HASH" ]]; then
  fail "createInstance failed: $CREATE_TX"
fi
ok "Transaction sent: $CREATE_TX_HASH"

# Wait for receipt and extract instance address from InstanceCreated event
step "Waiting for confirmation..."
sleep 3

RECEIPT=$(cast receipt "$CREATE_TX_HASH" --rpc-url "$CITREA_RPC" --json 2>/dev/null || echo "{}")
INSTANCE_ADDRESS=$(echo "$RECEIPT" | jq -r '
  .logs[]
  | select(.topics[0] == "0xa3de24f67beb38e771bb8aca2ec9e03485fedd4f4c7379d840ecc7cdd7f0700f")
  | .topics[1]
  | "0x" + .[-40:]
' 2>/dev/null | head -1)

if [[ -z "$INSTANCE_ADDRESS" || "$INSTANCE_ADDRESS" == "0x" ]]; then
  # Retry once
  sleep 5
  RECEIPT=$(cast receipt "$CREATE_TX_HASH" --rpc-url "$CITREA_RPC" --json 2>/dev/null || echo "{}")
  INSTANCE_ADDRESS=$(echo "$RECEIPT" | jq -r '
    .logs[]
    | select(.topics[0] == "0xa3de24f67beb38e771bb8aca2ec9e03485fedd4f4c7379d840ecc7cdd7f0700f")
    | .topics[1]
    | "0x" + .[-40:]
  ' 2>/dev/null | head -1)
fi

if [[ -z "$INSTANCE_ADDRESS" || "$INSTANCE_ADDRESS" == "0x" ]]; then
  fail "Could not extract instance address from receipt"
fi

CREATE_BLOCK=$(echo "$RECEIPT" | jq -r '.blockNumber' | python3 -c "import sys; h=sys.stdin.read().strip(); print(int(h,16) if h.startswith('0x') else h)")
ok "Instance deployed!"
ok "  Address:    $INSTANCE_ADDRESS"
ok "  Block:      $CREATE_BLOCK"
ok "  Explorer:   https://explorer.testnet.citrea.xyz/address/$INSTANCE_ADDRESS"

# ══════════════════════════════════════════════════════════════════
# SECTION 6: Execute Steps on L2
# ══════════════════════════════════════════════════════════════════

banner "6 · Executing Process Steps on Citrea"

TOTAL_STEPS=$(cast call "$INSTANCE_ADDRESS" "totalSteps()(uint256)" --rpc-url "$CITREA_RPC")
ok "Instance has $TOTAL_STEPS steps"

for (( i=0; i<TOTAL_STEPS; i++ )); do
  STEP_NAME=$(cast call "$INSTANCE_ADDRESS" "getStep(uint256)(string,string)" "$i" --rpc-url "$CITREA_RPC" 2>/dev/null | head -1 | tr -d '"')

  step "Step $((i+1))/$TOTAL_STEPS: $STEP_NAME"

  STEP_TX=$(cast send "$INSTANCE_ADDRESS" \
    "executeStep(uint8,string)" \
    1 \
    "Demo evidence for step $((i+1))" \
    --rpc-url "$CITREA_RPC" \
    --private-key "$CITREA_PRIVATE_KEY" \
    --json 2>&1)

  STEP_TX_HASH=$(echo "$STEP_TX" | jq -r '.transactionHash // empty')
  if [[ -z "$STEP_TX_HASH" ]]; then
    fail "executeStep($i) failed: $STEP_TX"
  fi
  ok "  tx: $STEP_TX_HASH"

  sleep 2
done

# Verify completion
IS_COMPLETED=$(cast call "$INSTANCE_ADDRESS" "completed()(bool)" --rpc-url "$CITREA_RPC")
CURRENT_IDX=$(cast call "$INSTANCE_ADDRESS" "currentStepIndex()(uint256)" --rpc-url "$CITREA_RPC")

if [[ "$IS_COMPLETED" == "true" ]]; then
  ok "Process COMPLETED ✅ (currentStepIndex: $CURRENT_IDX)"
else
  warn "Process not yet completed (currentStepIndex: $CURRENT_IDX)"
fi

# ══════════════════════════════════════════════════════════════════
# SECTION 7: Read Final Contract State
# ══════════════════════════════════════════════════════════════════

banner "7 · Final Contract State"

TEMPLATE_ON_CHAIN=$(cast call "$INSTANCE_ADDRESS" "templateInscriptionId()(string)" --rpc-url "$CITREA_RPC" | tr -d '"')
CREATOR=$(cast call "$INSTANCE_ADDRESS" "creator()(address)" --rpc-url "$CITREA_RPC")

echo "  ┌───────────────────────────────────────────────────┐"
echo "  │ Instance:     $INSTANCE_ADDRESS"
echo "  │ Template ID:  $TEMPLATE_ON_CHAIN"
echo "  │ Creator:      $CREATOR"
echo "  │ Total Steps:  $TOTAL_STEPS"
echo "  │ Current Step: $CURRENT_IDX"
echo "  │ Completed:    $IS_COMPLETED"
echo "  └───────────────────────────────────────────────────┘"

for (( i=0; i<TOTAL_STEPS; i++ )); do
  STATE=$(cast call "$INSTANCE_ADDRESS" "getStepState(uint256)(uint8,address,string,uint256)" "$i" --rpc-url "$CITREA_RPC" 2>/dev/null)
  STATUS_NUM=$(echo "$STATE" | head -1 | tr -d ' ')
  case "$STATUS_NUM" in
    0) STATUS_LABEL="Pending" ;;
    1) STATUS_LABEL="Completed ✅" ;;
    2) STATUS_LABEL="Rejected ❌" ;;
    *) STATUS_LABEL="Unknown($STATUS_NUM)" ;;
  esac
  STEP_NAME=$(cast call "$INSTANCE_ADDRESS" "getStep(uint256)(string,string)" "$i" --rpc-url "$CITREA_RPC" 2>/dev/null | head -1 | tr -d '"')
  info "  Step $((i+1)): $STEP_NAME → $STATUS_LABEL"
done

# ══════════════════════════════════════════════════════════════════
# SECTION 8: Bitcoin Settlement Finality
# ══════════════════════════════════════════════════════════════════

banner "8 · Bitcoin Settlement Finality"

step "Querying Citrea finality boundaries..."

COMMITTED=$(curl -sf -X POST "$CITREA_RPC" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"citrea_getLastCommittedL2Height","params":[],"id":1}' \
  | jq -r '.result.height')

PROVEN=$(curl -sf -X POST "$CITREA_RPC" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"citrea_getLastProvenL2Height","params":[],"id":1}' \
  | jq -r '.result.height')

ok "Last Committed L2 height: $COMMITTED"
ok "Last Proven L2 height:    $PROVEN"

# Classify our creation block
if [[ "$CREATE_BLOCK" -le "$PROVEN" ]]; then
  FINALITY="✅ ZK-PROVEN on Bitcoin"
elif [[ "$CREATE_BLOCK" -le "$COMMITTED" ]]; then
  FINALITY="🔵 COMMITTED to Bitcoin (not yet proven)"
else
  FINALITY="🟡 SOFT CONFIRMATION (not yet committed)"
fi

echo ""
echo "  Instance creation block: $CREATE_BLOCK"
echo "  Finality status:         $FINALITY"

if [[ "$CREATE_BLOCK" -gt "$COMMITTED" ]]; then
  GAP=$((CREATE_BLOCK - COMMITTED))
  info "Gap to committed: $GAP blocks (~$((GAP / 1000)) batches)"
  info "The sequencer will commit this block in a future batch."
  info "Re-check with: curl -s $CITREA_RPC -d '{\"jsonrpc\":\"2.0\",\"method\":\"citrea_getLastCommittedL2Height\",\"params\":[],\"id\":1}'"
fi

# ══════════════════════════════════════════════════════════════════
# SECTION 9: Summary
# ══════════════════════════════════════════════════════════════════

banner "9 · Demo Complete!"

echo "  ┌─────────────────────────────────────────────────────────────┐"
echo "  │                    BINST E2E Demo Results                   │"
echo "  ├─────────────────────────────────────────────────────────────┤"
if ! $L2_ONLY; then
echo "  │ L1 Institution:    $INSTITUTION_ID"
echo "  │ L1 Template:       $TEMPLATE_ID"
fi
echo "  │ L2 Factory:        $FACTORY_ADDRESS"
echo "  │ L2 Instance:       $INSTANCE_ADDRESS"
echo "  │ L2 Creator:        $CITREA_ADDRESS"
echo "  │ Steps completed:   $CURRENT_IDX / $TOTAL_STEPS"
echo "  │ Process completed: $IS_COMPLETED"
echo "  │ Finality:          $FINALITY"
echo "  └─────────────────────────────────────────────────────────────┘"
echo ""
echo "  Explore on-chain:"
echo "    Instance: https://explorer.testnet.citrea.xyz/address/$INSTANCE_ADDRESS"
echo "    Factory:  https://explorer.testnet.citrea.xyz/address/$FACTORY_ADDRESS"
if ! $L2_ONLY && [[ -n "$INST_REVEAL" ]]; then
echo "    Institution tx: $MEMPOOL_API/tx/$INST_REVEAL"
echo "    Template tx:    $MEMPOOL_API/tx/$TMPL_REVEAL"
fi
echo ""
echo "  Use the binst CLI for further queries:"
echo "    binst instance --address $INSTANCE_ADDRESS"
echo "    binst finality --tx $CREATE_TX_HASH"
echo "    binst factory --template \"$TEMPLATE_ID\""
echo ""
ok "Done! The BINST protocol lifecycle is complete."
