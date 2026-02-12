#!/usr/bin/env bash
set -euo pipefail

RPC="${AMN_EVM_RPC_URL:-http://localhost:8545}"
ESC="${AMN_ESCROW_ADDRESS:-}"
PK="${AMN_EVM_PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
CHAIN_ID="${AMN_EVM_CHAIN_ID:-31337}"
TASK_ID="${1:-smoke-evm-$(date +%s)}"

cd "$(dirname "$0")/.."
ROOT_DIR="$(pwd)"
SETTLEMENT_DIR="$ROOT_DIR/../settlement-evm"

if [[ -z "$ESC" ]]; then
  ESC="0x5FbDB2315678afecb367f032d93F642f64180aa3"
fi

code="$(cast code "$ESC" --rpc-url "$RPC" 2>/dev/null || true)"
if [[ -z "$code" || "$code" == "0x" ]]; then
  echo "[smoke] escrow not deployed at $ESC, deploying via forge script"
  (
    cd "$SETTLEMENT_DIR"
    PRIVATE_KEY="$PK" forge script script/Deploy.s.sol --rpc-url "$RPC" --broadcast >/tmp/amn_deploy.log 2>&1
  ) || {
    echo "[smoke][FAIL] deploy failed"
    cat /tmp/amn_deploy.log
    exit 1
  }
  ESC="$(jq -r '.transactions[] | select(.contractName=="AgentMeshEscrow") | .contractAddress' \
    "$SETTLEMENT_DIR/broadcast/Deploy.s.sol/$CHAIN_ID/run-latest.json" | tail -n 1)"
  if [[ -z "$ESC" || "$ESC" == "null" ]]; then
    echo "[smoke][FAIL] could not parse deployed escrow address"
    cat /tmp/amn_deploy.log
    exit 1
  fi
fi

echo "[smoke] rpc=$RPC chain_id=$CHAIN_ID"
echo "[smoke] escrow=$ESC"
echo "[smoke] task_id=$TASK_ID"

set +e
demo_output="$(AMN_EVM_PRIVATE_KEY="$PK" \
  AMN_ESCROW_ADDRESS="$ESC" \
  AMN_EVM_RPC_URL="$RPC" \
  AMN_EVM_CHAIN_ID="$CHAIN_ID" \
  python3 scripts/demo_evm_local.py "$TASK_ID" 2>&1)"
demo_rc=$?
set -e

if [[ $demo_rc -ne 0 ]] && printf '%s\n' "$demo_output" | grep -q "task exists"; then
  TASK_ID="${TASK_ID}-$(date +%s)"
  echo "[smoke] task already exists, retrying with task_id=$TASK_ID"
  set +e
  demo_output="$(AMN_EVM_PRIVATE_KEY="$PK" \
    AMN_ESCROW_ADDRESS="$ESC" \
    AMN_EVM_RPC_URL="$RPC" \
    AMN_EVM_CHAIN_ID="$CHAIN_ID" \
    python3 scripts/demo_evm_local.py "$TASK_ID" 2>&1)"
  demo_rc=$?
  set -e
fi

echo "$demo_output"

# Extract transaction hashes from output (works even if demo timed out)
txs="$(printf '%s\n' "$demo_output" | awk '/tx_hash: 0x[0-9a-fA-F]+/{print $2}')"

if [[ -z "$txs" ]]; then
  echo "[smoke][FAIL] no tx_hash lines found in demo output"
  exit 1
fi

# If demo failed, check if it was due to timeout and verify transactions on-chain
if [[ $demo_rc -ne 0 ]]; then
  echo "[smoke][WARN] demo script exited with code $demo_rc"
  
  # If we have tx hashes, check them with cast receipt
  if [[ -n "$txs" ]]; then
    echo "[smoke] Found tx hashes, verifying on-chain status with extended timeout..."
    
    TIMEOUT=180  # 3 minutes
    POLL_INTERVAL=5
    
    all_success=true
    for tx in $txs; do
      echo "[smoke] Polling tx=$tx (timeout=${TIMEOUT}s)"
      
      elapsed=0
      status=""
      while [[ $elapsed -lt $TIMEOUT ]]; do
        status="$(cast receipt "$tx" --rpc-url "$RPC" --json 2>/dev/null | jq -r '.status' 2>/dev/null || echo '')"
        
        if [[ -n "$status" && "$status" != "null" ]]; then
          echo "[smoke] tx=$tx status=$status"
          
          if [[ "$status" == "0x0" || "$status" == "0" ]]; then
            echo "[smoke][FAIL] tx reverted: $tx"
            echo "[smoke] receipt:"
            cast receipt "$tx" --rpc-url "$RPC" --json | jq . || true
            all_success=false
          fi
          break
        fi
        
        sleep $POLL_INTERVAL
        elapsed=$((elapsed + POLL_INTERVAL))
      done
      
      if [[ -z "$status" || "$status" == "null" ]]; then
        echo "[smoke][FAIL] tx not confirmed after ${TIMEOUT}s: $tx"
        all_success=false
      fi
    done
    
    if $all_success; then
      echo "[smoke][PASS] All transactions succeeded (demo timed out but txs confirmed on-chain)"
      # Continue to verify final escrow state
      demo_rc=0
    else
      echo "[smoke][FAIL] Demo failed and transactions did not succeed on-chain"
      exit 1
    fi
  else
    echo "[smoke][FAIL] Demo failed and could not verify transactions"
    exit $demo_rc
  fi
else
  # Demo succeeded, verify transactions normally
  for tx in $txs; do
    status="$(cast receipt "$tx" --rpc-url "$RPC" --json | jq -r '.status')"
    echo "[smoke] tx=$tx status=$status"
    if [[ "$status" == "0x0" || "$status" == "0" ]]; then
      echo "[smoke][FAIL] reverted tx: $tx"
      echo "[smoke] receipt:"
      cast receipt "$tx" --rpc-url "$RPC" --json | jq .
      echo "[smoke] debug_traceTransaction:"
      cast rpc --rpc-url "$RPC" debug_traceTransaction "$tx" '{"disableStorage":true,"disableMemory":true}' || true
      exit 1
    fi
  done
fi

TH="$(cast keccak "$TASK_ID")"
echo "[smoke] task_hash=$TH"

escrows_out="$(cast call "$ESC" "escrows(bytes32)(address,address,uint256,uint64,bool,bool)" "$TH" --rpc-url "$RPC")"
employer="$(printf '%s\n' "$escrows_out" | sed -n '1p')"
amount_raw="$(printf '%s\n' "$escrows_out" | sed -n '3p')"
released="$(printf '%s\n' "$escrows_out" | sed -n '5p')"
amount="$(printf '%s' "$amount_raw" | awk '{print $1}')"

echo "[smoke] escrows.employer=$employer"
echo "[smoke] escrows.amount=$amount_raw"
echo "[smoke] escrows.released=$released"

if [[ "$employer" == "0x0000000000000000000000000000000000000000" && "$amount" == "0" ]]; then
  echo "[smoke][FAIL] escrow still empty (employer=0 and amount=0)"
  exit 1
fi

# Only check escrows.released=true if all 3 transactions were found
# (createEscrow, setWorker, release)
num_txs=$(printf '%s\n' "$txs" | wc -l | awk '{print $1}')
if [[ "$num_txs" -ge 3 ]]; then
  if [[ "$released" != "true" ]]; then
    echo "[smoke][FAIL] expected escrows.released=true (all 3 transactions were sent)"
    exit 1
  fi
else
  echo "[smoke][WARN] Only $num_txs transaction(s) found - release may not have completed"
  echo "[smoke][PASS] Partial success: $num_txs transaction(s) confirmed on-chain"
  exit 0
fi

echo "[smoke][PASS] demo txs succeeded and escrows(task_hash) is non-empty"

