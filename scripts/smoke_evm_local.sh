#!/usr/bin/env bash
set -euo pipefail

RPC="${AMN_EVM_RPC_URL:-http://localhost:8545}"
ESC="${AMN_ESCROW_ADDRESS:-0x5FbDB2315678afecb367f032d93F642f64180aa3}"
PK="${AMN_EVM_PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
CHAIN_ID="${AMN_EVM_CHAIN_ID:-31337}"
TASK_ID="${1:-smoke-evm-$(date +%s)}"

cd "$(dirname "$0")/.."

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

echo "$demo_output"

txs="$(printf '%s\n' "$demo_output" | awk '/tx_hash: 0x[0-9a-fA-F]+/{print $2}')"

if [[ -z "$txs" ]]; then
  echo "[smoke][FAIL] no tx_hash lines found in demo output"
  exit 1
fi

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

if [[ $demo_rc -ne 0 ]]; then
  echo "[smoke][FAIL] demo script failed"
  exit $demo_rc
fi

TH="$(cast keccak "$TASK_ID")"
echo "[smoke] task_hash=$TH"

escrows_out="$(cast call "$ESC" "escrows(bytes32)(address,address,uint256,uint64,bool,bool)" "$TH" --rpc-url "$RPC")"
employer="$(printf '%s\n' "$escrows_out" | sed -n '1p')"
amount_raw="$(printf '%s\n' "$escrows_out" | sed -n '3p')"
amount="$(printf '%s' "$amount_raw" | awk '{print $1}')"

echo "[smoke] escrows.employer=$employer"
echo "[smoke] escrows.amount=$amount_raw"

if [[ "$employer" == "0x0000000000000000000000000000000000000000" && "$amount" == "0" ]]; then
  echo "[smoke][FAIL] escrow still empty (employer=0 and amount=0)"
  exit 1
fi

echo "[smoke][PASS] demo txs succeeded and escrows(task_hash) is non-empty"
