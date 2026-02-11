"""EVM escrow adapter for AgentMesh-Net settlement.

This module talks to the AgentMeshEscrow smart contract
(settlement-evm-v0.2.0) via web3.py.  It is fully optional and does
NOT import any core protocol modules (envelope, identity, etc.).

Environment variables (all overridable via constructor args):
    AMN_EVM_RPC_URL       – JSON-RPC endpoint  (default http://localhost:8545)
    AMN_EVM_PRIVATE_KEY   – hex-encoded private key
    AMN_ESCROW_ADDRESS    – deployed AgentMeshEscrow address
    AMN_EVM_CHAIN_ID      – chain id (default 31337 for Anvil)
    AMN_EVM_TIMEOUT       – tx wait timeout in seconds (default 30)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from eth_account import Account
from eth_utils import keccak
from web3 import Web3
from web3._utils.events import EventLogErrorFlags

# ---------------------------------------------------------------------------
# ABI loading
# ---------------------------------------------------------------------------
_ABI_PATH = Path(__file__).parent / "abi" / "AgentMeshEscrow.json"

def _load_abi() -> list[dict[str, Any]]:
    with open(_ABI_PATH) as f:
        raw = json.load(f)

    # Accept either:
    # 1) a plain ABI list
    # 2) a foundry artifact object with an `abi` field
    if isinstance(raw, list):
        abi = raw
    elif isinstance(raw, dict) and isinstance(raw.get("abi"), list):
        abi = raw["abi"]
    else:
        raise ValueError(f"Unsupported ABI JSON shape in {_ABI_PATH}")

    # Some hand-written ABI snippets omit `anonymous` on event entries.
    normalized: list[dict[str, Any]] = []
    for item in abi:
        if isinstance(item, dict) and item.get("type") == "event" and "anonymous" not in item:
            item = {**item, "anonymous": False}
        normalized.append(item)
    return normalized

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
ESCROW_STATES = {0: "Open", 1: "Released", 2: "Refunded"}


def task_hash(task_id: str) -> bytes:
    """Return the keccak-256 hash of *task_id* as 32 bytes.

    This matches the on-chain derivation:
        bytes32 taskHash = keccak256(abi.encodePacked(taskIdString))
    which for a plain UTF-8 string is just keccak256(bytes(task_id)).
    """
    return keccak(task_id.encode("utf-8"))


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
class EvmEscrowClient:
    """Thin wrapper around the AgentMeshEscrow contract."""

    def __init__(
        self,
        rpc_url: str | None = None,
        private_key: str | None = None,
        contract_address: str | None = None,
        chain_id: int | None = None,
        timeout: int | None = None,
    ):
        self.rpc_url = rpc_url or os.environ.get(
            "AMN_EVM_RPC_URL", "http://localhost:8545"
        )
        pk = private_key or os.environ["AMN_EVM_PRIVATE_KEY"]
        self.contract_address = Web3.to_checksum_address(
            contract_address or os.environ["AMN_ESCROW_ADDRESS"]
        )
        self.chain_id = chain_id or int(
            os.environ.get("AMN_EVM_CHAIN_ID", "31337")
        )
        self.timeout = timeout or int(os.environ.get("AMN_EVM_TIMEOUT", "30"))

        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        self.account = Account.from_key(pk)
        self.address = self.account.address

        abi = _load_abi()
        self.contract = self.w3.eth.contract(
            address=self.contract_address, abi=abi
        )

    # -- internal tx helpers ------------------------------------------------

    def _send(self, fn, value: int = 0) -> bytes:
        """Build, sign and send a contract function call.  Returns tx hash."""
        tx = fn.build_transaction(
            {
                "from": self.address,
                "value": value,
                "nonce": self.w3.eth.get_transaction_count(self.address),
                "gas": 300_000,
                "gasPrice": self.w3.eth.gas_price,
                "chainId": self.chain_id,
            }
        )
        signed = self.account.sign_transaction(tx)
        return self.w3.eth.send_raw_transaction(signed.raw_transaction)

    # -- public API ---------------------------------------------------------

    def create_escrow(
        self, task_id: str, amount_wei: int, deadline_unix: int
    ) -> bytes:
        """Send createEscrow(taskHash, deadline) with *amount_wei* value."""
        if deadline_unix < 0 or deadline_unix > (2**64 - 1):
            raise ValueError("deadline_unix out of uint64 range")
        th = task_hash(task_id)
        fn = self.contract.functions.createEscrow(th, int(deadline_unix))
        return self._send(fn, value=amount_wei)

    def set_worker(self, task_id: str, worker_address: str) -> bytes:
        """Send setWorker(taskHash, worker)."""
        th = task_hash(task_id)
        worker = Web3.to_checksum_address(worker_address)
        fn = self.contract.functions.setWorker(th, worker)
        return self._send(fn)

    def release(self, task_id: str) -> bytes:
        """Send release(taskHash)."""
        th = task_hash(task_id)
        fn = self.contract.functions.release(th)
        return self._send(fn)

    def refund(self, task_id: str) -> bytes:
        """Send refund(taskHash)."""
        th = task_hash(task_id)
        fn = self.contract.functions.refund(th)
        return self._send(fn)

    def get_escrow(self, task_id: str) -> dict:
        """Read escrow struct from chain.  Returns a plain dict."""
        th = task_hash(task_id)
        employer, worker, amount, deadline, released, refunded = (
            self.contract.functions.escrows(th).call()
        )
        state = "Refunded" if refunded else ("Released" if released else "Open")
        return {
            "employer": employer,
            # Back-compat alias for earlier demo output naming.
            "depositor": employer,
            "worker": worker,
            "amount": amount,
            "deadline": deadline,
            "released": released,
            "refunded": refunded,
            "state": state,
        }

    def get_fee_params(self) -> dict:
        """Read feeRecipient and feeBps from contract."""
        return {
            "feeRecipient": self.contract.functions.feeRecipient().call(),
            "feeBps": self.contract.functions.feeBps().call(),
        }

    def wait_receipt(self, tx_hash: bytes) -> dict:
        """Block until tx is mined and return the receipt."""
        return self.w3.eth.wait_for_transaction_receipt(
            tx_hash, timeout=self.timeout
        )

    def tx_failure_details(self, tx_hash: bytes) -> str:
        """Best-effort failure details for a reverted transaction."""
        tx_hex = tx_hash.hex() if isinstance(tx_hash, (bytes, bytearray)) else str(tx_hash)
        details = [f"tx={tx_hex}"]
        try:
            tx = self.w3.eth.get_transaction(tx_hash)
            call = {
                "from": tx.get("from"),
                "to": tx.get("to"),
                "data": tx.get("input"),
                "value": tx.get("value", 0),
            }
            block_num = tx.get("blockNumber")
            block_id = block_num - 1 if isinstance(block_num, int) and block_num > 0 else "latest"
            self.w3.eth.call(call, block_identifier=block_id)
            details.append("eth_call: no revert data")
        except Exception as e:
            details.append(f"eth_call error: {e}")

        try:
            trace = self.w3.provider.make_request(
                "debug_traceTransaction",
                [tx_hex, {"disableMemory": True, "disableStorage": True}],
            )
            if "error" in trace:
                details.append(f"debug_trace error: {trace['error']}")
            else:
                details.append("debug_traceTransaction available")
        except Exception as e:
            details.append(f"debug_trace error: {e}")

        return " | ".join(details)

    def decode_events(self, receipt: dict) -> list[dict]:
        """Decode all known AgentMeshEscrow events from a receipt."""
        events: list[dict] = []
        # Prefer current contract event names; keep legacy aliases for output.
        event_names = (
            "EscrowCreated",
            "WorkerSet",
            "EscrowReleased",
            "EscrowRefunded",
            "Created",
            "Released",
            "Refunded",
        )
        legacy_map = {
            "EscrowCreated": "Created",
            "EscrowReleased": "Released",
            "EscrowRefunded": "Refunded",
        }
        for event_name in event_names:
            if not hasattr(self.contract.events, event_name):
                continue
            processor = getattr(self.contract.events, event_name)().process_receipt(
                receipt, errors=EventLogErrorFlags.Discard
            )
            for log in processor:
                args = dict(log["args"])
                # Back-compat: old demo expected Released.payout while current
                # contract emits EscrowReleased.amount.
                if legacy_map.get(event_name, event_name) == "Released":
                    if "payout" not in args and "amount" in args:
                        args["payout"] = args["amount"]
                events.append(
                    {
                        "event": legacy_map.get(event_name, event_name),
                        "raw_event": event_name,
                        "args": args,
                    }
                )
        return events
