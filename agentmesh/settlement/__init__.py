"""Optional EVM settlement adapter for AgentMesh-Net.

Install with:  pip install -e ".[evm]"
"""

from .evm import EVMAdapter, EvmEscrowClient, task_hash
from .exceptions import SettlementError, SettlementMisconfiguration, SettlementRevert, SettlementTimeout
from .service import SettlementService, compute_task_hash
from .types import SettlementCreateResult, SettlementState

__all__ = [
    "EVMAdapter",
    "EvmEscrowClient",
    "SettlementCreateResult",
    "SettlementError",
    "SettlementMisconfiguration",
    "SettlementRevert",
    "SettlementService",
    "SettlementState",
    "SettlementTimeout",
    "compute_task_hash",
    "task_hash",
]
