"""High-level settlement API bound to protocol task object_id values.

Settlement layer assumes `task_id` is the canonical indexer task `object_id`.
On-chain key derivation is deterministic: keccak256(bytes(task_id)).
"""

from __future__ import annotations

import logging
from typing import Optional

from .evm import task_hash
from .exceptions import SettlementError, SettlementMisconfiguration, SettlementRevert
from .types import SettlementCreateResult, SettlementState

_LOG = logging.getLogger(__name__)
_ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


def compute_task_hash(task_id: str) -> str:
    """Return 0x-prefixed task hash from canonical indexer task_id."""
    return "0x" + task_hash(task_id).hex()


class SettlementService:
    def __init__(self, evm_adapter):
        self.evm = evm_adapter

    def _send_and_confirm(self, tx_hash_bytes) -> str:
        tx_hash = tx_hash_bytes.hex()
        tx_hash_hex = tx_hash if tx_hash.startswith("0x") else f"0x{tx_hash}"
        receipt = self.evm.wait_receipt(tx_hash_bytes)
        status = int(receipt.get("status", 0))
        _LOG.info("settlement tx=%s status=%s", tx_hash_hex, status)
        if status == 0:
            details = self.evm.tx_failure_details(tx_hash_bytes)
            raise SettlementRevert(f"transaction reverted: {details}")
        return tx_hash_hex

    def settle_create(
        self, task_id: str, amount_wei: int, deadline_unix: int
    ) -> SettlementCreateResult:
        tx = self.evm.create_escrow(task_id, amount_wei, deadline_unix)
        tx_hash = self._send_and_confirm(tx)
        return SettlementCreateResult(tx_hash=tx_hash, task_hash=compute_task_hash(task_id))

    def settle_set_worker(
        self,
        task_id: str,
        worker_address: str,
        accept_signer_address: Optional[str] = None,
        accept_signer_pubkey: Optional[str] = None,
        expected_accept_signer_pubkey: Optional[str] = None,
    ) -> str:
        if accept_signer_address is not None and worker_address.lower() != accept_signer_address.lower():
            raise SettlementError("worker address must match provided accept signer address")
        # Optional invariant hook for protocol binding when signer identity is supplied.
        if (
            accept_signer_pubkey is not None
            and expected_accept_signer_pubkey is not None
            and accept_signer_pubkey != expected_accept_signer_pubkey
        ):
            raise SettlementError("accept signer mismatch before setWorker")
        tx = self.evm.set_worker(task_id, worker_address)
        return self._send_and_confirm(tx)

    def settle_release(self, task_id: str) -> str:
        state = self.get_settlement_state(task_id)
        if state.worker.lower() == _ZERO_ADDRESS:
            raise SettlementMisconfiguration("cannot release before worker is set")
        tx = self.evm.release(task_id)
        return self._send_and_confirm(tx)

    def settle_refund(self, task_id: str) -> str:
        tx = self.evm.refund(task_id)
        return self._send_and_confirm(tx)

    def get_settlement_state(self, task_id: str) -> SettlementState:
        raw = self.evm.get_escrow(task_id)
        return SettlementState(
            employer=raw["employer"],
            worker=raw["worker"],
            amount=int(raw["amount"]),
            deadline=int(raw["deadline"]),
            released=bool(raw["released"]),
            refunded=bool(raw["refunded"]),
            state=str(raw["state"]),
        )
