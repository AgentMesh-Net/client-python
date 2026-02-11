#!/usr/bin/env python3
"""Demo: drive an AgentMeshEscrow lifecycle on a local Anvil node.

Prerequisites
─────────────
1. Anvil running at localhost:8545
2. AgentMeshEscrow deployed (settlement-evm-v0.2.0)
3. Environment variables set:
     AMN_EVM_PRIVATE_KEY   – hex key of Anvil account #0  (deployer/depositor)
     AMN_ESCROW_ADDRESS    – deployed contract address

Optional env:
     AMN_EVM_RPC_URL       – defaults to http://localhost:8545
     AMN_EVM_CHAIN_ID      – defaults to 31337

Usage:
    python scripts/demo_evm_local.py [task_id]
"""

from __future__ import annotations

import sys
import time

from agentmesh.settlement.evm import EvmEscrowClient, task_hash
from web3 import Web3

# Anvil default account #1 (worker)
ANVIL_ACCOUNT_1 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

ONE_ETHER = 10**18


def main() -> None:
    task_id = sys.argv[1] if len(sys.argv) > 1 else "demo-task-001"

    print(f"task_id          = {task_id}")
    print(f"task_hash        = 0x{task_hash(task_id).hex()}")
    print()

    client = EvmEscrowClient()
    print(f"RPC              = {client.rpc_url}")
    print(f"Escrow contract  = {client.contract_address}")
    print(f"Depositor        = {client.address}")
    print(f"Worker           = {ANVIL_ACCOUNT_1}")
    print()

    # fee params
    fee = client.get_fee_params()
    print(f"Fee recipient    = {fee['feeRecipient']}")
    print(f"Fee bps          = {fee['feeBps']}")
    print()

    amount = ONE_ETHER
    deadline = int(time.time()) + 3600

    # 1) create escrow
    print("--- createEscrow ---")
    tx = client.create_escrow(task_id, amount, deadline)
    print(f"  tx_hash: 0x{tx.hex()}")
    receipt = client.wait_receipt(tx)
    status = receipt.get("status", 0)
    print(f"  status: {status}")
    if status == 0:
        raise RuntimeError(client.tx_failure_details(tx))
    for ev in client.decode_events(receipt):
        print(f"  event: {ev['event']}  args: {ev['args']}")
    print()

    # 2) set worker
    print("--- setWorker ---")
    tx = client.set_worker(task_id, ANVIL_ACCOUNT_1)
    print(f"  tx_hash: 0x{tx.hex()}")
    receipt = client.wait_receipt(tx)
    status = receipt.get("status", 0)
    print(f"  status: {status}")
    if status == 0:
        raise RuntimeError(client.tx_failure_details(tx))
    for ev in client.decode_events(receipt):
        print(f"  event: {ev['event']}  args: {ev['args']}")
    print()

    # 3) release
    print("--- release ---")
    tx = client.release(task_id)
    print(f"  tx_hash: 0x{tx.hex()}")
    receipt = client.wait_receipt(tx)
    status = receipt.get("status", 0)
    print(f"  status: {status}")
    if status == 0:
        raise RuntimeError(client.tx_failure_details(tx))
    events = client.decode_events(receipt)
    for ev in events:
        print(f"  event: {ev['event']}  args: {ev['args']}")
    print()

    # 4) fee math
    for ev in events:
        if ev["event"] == "Released":
            payout = ev["args"].get("payout", ev["args"].get("amount"))
            if payout is None:
                raise RuntimeError(f"Released event missing payout/amount fields: {ev['args']}")
            fee_amt = ev["args"]["fee"]
            print("--- Fee verification ---")
            print(f"  amount deposited = {amount} wei  ({Web3.from_wei(amount, 'ether')} ETH)")
            print(f"  payout           = {payout} wei")
            print(f"  fee              = {fee_amt} wei")
            expected_fee = amount * fee["feeBps"] // 10_000
            print(f"  expected fee     = {expected_fee} wei  (amount * {fee['feeBps']} / 10000)")
            assert fee_amt == expected_fee, f"fee mismatch: {fee_amt} != {expected_fee}"
            assert payout == amount - expected_fee
            print("  PASS: fee math correct")
    print()

    # 5) final state
    state = client.get_escrow(task_id)
    print(f"Final escrow state: {state}")


if __name__ == "__main__":
    main()
