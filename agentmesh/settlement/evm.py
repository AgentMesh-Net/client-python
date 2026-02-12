"""EVM escrow adapter for AgentMesh-Net settlement.

This module talks to the AgentMeshEscrow smart contract
(settlement-evm-v0.2.0) via web3.py.  It is fully optional and does
NOT import any core protocol modules (envelope, identity, etc.).

Environment variables (all overridable via constructor args):
    AMN_EVM_RPC_URL       – JSON-RPC endpoint  (default http://localhost:8545)
    AMN_EVM_PRIVATE_KEY   – hex-encoded private key
    AMN_ESCROW_ADDRESS    – deployed AgentMeshEscrow address
    AMN_EVM_CHAIN_ID      – chain id (default 31337 for Anvil)
    AMN_TX_TIMEOUT        – tx wait timeout in seconds (default 30)
    AMN_EVM_TIMEOUT       – legacy alias for AMN_TX_TIMEOUT
    AMN_TX_POLL           – poll latency in seconds (default 2)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from eth_account import Account
from eth_utils import keccak
from hexbytes import HexBytes
from web3 import Web3
from web3._utils.events import EventLogErrorFlags
from web3.exceptions import TimeExhausted

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
        poll_latency: int | None = None,
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
        # Support both AMN_TX_TIMEOUT (preferred) and AMN_EVM_TIMEOUT (legacy)
        self.timeout = timeout or int(
            os.environ.get("AMN_TX_TIMEOUT") or 
            os.environ.get("AMN_EVM_TIMEOUT", "30")
        )
        self.poll_latency = poll_latency or int(os.environ.get("AMN_TX_POLL", "2"))

        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        self.account = Account.from_key(pk)
        self.address = self.account.address

        abi = _load_abi()
        self.contract = self.w3.eth.contract(
            address=self.contract_address, abi=abi
        )

    @classmethod
    def from_env(cls) -> "EvmEscrowClient":
        """Build adapter from environment variables."""
        return cls()

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

    def wait_receipt(self, tx_hash: bytes | str) -> dict:
        """Block until tx is mined and return the receipt.
        
        Raises:
            SettlementTimeout: If transaction is not confirmed within timeout period.
                This doesn't mean the transaction failed - check the explorer link.
        """
        from .exceptions import SettlementTimeout
        
        tx_hash = self._normalize_tx_hash(tx_hash)
        try:
            return self.w3.eth.wait_for_transaction_receipt(
                tx_hash, timeout=self.timeout, poll_latency=self.poll_latency
            )
        except TimeExhausted:
            tx_hex = tx_hash.hex() if tx_hash.hex().startswith("0x") else f"0x{tx_hash.hex()}"
            explorer_url = self._get_explorer_url(tx_hex)
            
            error_msg = (
                f"\n\n⏱️  Transaction confirmation timeout after {self.timeout} seconds\n\n"
                f"This doesn't mean the transaction failed! The timeout expired while waiting\n"
                f"for the blockchain to confirm your transaction, but it may still succeed.\n\n"
                f"Transaction: {tx_hex}\n"
                f"Check status: {explorer_url}\n\n"
                f"To avoid this timeout in the future, increase the wait time:\n"
                f"  export AMN_TX_TIMEOUT=\"120\"  # seconds\n\n"
                f"You can also check manually:\n"
                f"  cast receipt {tx_hex} --rpc-url $AMN_EVM_RPC_URL\n\n"
                f"Current timeout: {self.timeout}s\n"
            )
            
            # Add network-specific suggestions
            if self.chain_id == 11155111:  # Sepolia
                error_msg += "Suggested timeout for Sepolia: 120s\n"
            elif self.chain_id == 1:  # Mainnet
                error_msg += "Suggested timeout for Mainnet: 180s\n"
            elif self.chain_id in [5, 421613]:  # Goerli, Arbitrum Goerli
                error_msg += "Suggested timeout for testnets: 120s\n"
            
            raise SettlementTimeout(error_msg) from None

    def _get_explorer_url(self, tx_hash: str) -> str:
        """Generate blockchain explorer URL for a transaction hash.
        
        Args:
            tx_hash: Transaction hash with 0x prefix
            
        Returns:
            Full URL to view transaction on appropriate explorer
        """
        # Ensure 0x prefix
        if not tx_hash.startswith("0x"):
            tx_hash = f"0x{tx_hash}"
        
        # Map chain IDs to explorer base URLs
        explorers = {
            1: "https://etherscan.io",           # Ethereum Mainnet
            5: "https://goerli.etherscan.io",    # Goerli Testnet
            11155111: "https://sepolia.etherscan.io",  # Sepolia Testnet
            10: "https://optimistic.etherscan.io",     # Optimism
            42161: "https://arbiscan.io",        # Arbitrum One
            137: "https://polygonscan.com",      # Polygon
            # Local/dev chains - no explorer
            31337: None,  # Anvil
            1337: None,   # Hardhat
        }
        
        base_url = explorers.get(self.chain_id)
        if base_url:
            return f"{base_url}/tx/{tx_hash}"
        else:
            # For unknown chains or local networks
            return f"No explorer available for chain {self.chain_id}. Transaction: {tx_hash}"
    
    def _normalize_tx_hash(self, tx_hash: bytes | str) -> HexBytes:
        """Normalize bytes/hex-string tx hash into HexBytes."""
        if isinstance(tx_hash, (bytes, bytearray)):
            return HexBytes(tx_hash)
        if isinstance(tx_hash, str):
            s = tx_hash.strip()
            if not s.startswith("0x"):
                s = "0x" + s
            return HexBytes(s)
        raise TypeError(f"unsupported tx_hash type: {type(tx_hash)!r}")

    def tx_failure_details(self, tx_hash: bytes | str) -> str:
        """Best-effort failure details for a reverted transaction."""
        tx_hash = self._normalize_tx_hash(tx_hash)
        tx_hex = tx_hash.hex()
        if not tx_hex.startswith("0x"):
            tx_hex = "0x" + tx_hex
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


# Preferred public adapter alias used by higher-level settlement service/demo.
EVMAdapter = EvmEscrowClient
