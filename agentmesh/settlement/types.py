from dataclasses import dataclass


@dataclass
class SettlementCreateResult:
    tx_hash: str
    task_hash: str


@dataclass
class SettlementState:
    employer: str
    worker: str
    amount: int
    deadline: int
    released: bool
    refunded: bool
    state: str
