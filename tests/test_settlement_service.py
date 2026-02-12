"""Integration tests for the high-level SettlementService."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from agentmesh.settlement import EVMAdapter, SettlementRevert, SettlementService

RPC_URL = "http://localhost:8545"
CHAIN_ID = 31337
ANVIL_PK0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANVIL_WORKER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"


def _rpc_ready() -> bool:
    probe = subprocess.run(
        [
            "curl",
            "-s",
            "-X",
            "POST",
            RPC_URL,
            "-H",
            "content-type: application/json",
            "--data",
            '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}',
        ],
        capture_output=True,
        text=True,
    )
    return probe.returncode == 0 and '"result"' in (probe.stdout or "")


def _deploy_escrow() -> str:
    repo_root = Path(__file__).resolve().parents[2]
    settlement_dir = repo_root / "settlement-evm"
    run_latest = settlement_dir / "broadcast" / "Deploy.s.sol" / str(CHAIN_ID) / "run-latest.json"

    env = dict(os.environ)
    env["PRIVATE_KEY"] = ANVIL_PK0
    proc = subprocess.run(
        [
            "forge",
            "script",
            "script/Deploy.s.sol",
            "--rpc-url",
            RPC_URL,
            "--broadcast",
        ],
        cwd=settlement_dir,
        capture_output=True,
        text=True,
        env=env,
    )
    candidates: list[str] = []
    if run_latest.exists():
        data = json.loads(run_latest.read_text())
        for tx in data.get("transactions", []):
            addr = tx.get("contractAddress")
            if tx.get("contractName") == "AgentMeshEscrow" and addr:
                candidates.append(addr)

    for line in (proc.stdout or "").splitlines():
        m = re.search(r"AgentMeshEscrow deployed at:\s*(0x[a-fA-F0-9]{40})", line)
        if m:
            candidates.append(m.group(1))

    # Fallback to common deterministic anvil deployment address.
    candidates.append("0x5FbDB2315678afecb367f032d93F642f64180aa3")

    for addr in candidates:
        code = subprocess.run(
            ["cast", "code", addr, "--rpc-url", RPC_URL],
            capture_output=True,
            text=True,
        )
        if code.returncode == 0 and code.stdout.strip() not in ("", "0x"):
            return addr

    if proc.returncode != 0:
        raise RuntimeError(
            f"forge deploy failed\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    raise RuntimeError("unable to parse deployed escrow address from run-latest.json")


@pytest.fixture(scope="session", autouse=True)
def _ensure_tools():
    missing = [tool for tool in ("curl", "cast", "forge", "anvil") if shutil.which(tool) is None]
    if missing:
        pytest.skip(f"missing required tools: {', '.join(missing)}")


@pytest.fixture(scope="session")
def anvil_proc():
    if _rpc_ready():
        yield None
        return

    proc = subprocess.Popen(
        ["anvil", "--host", "127.0.0.1", "--port", "8545"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(50):
        if _rpc_ready():
            break
        time.sleep(0.2)
    else:
        proc.terminate()
        raise RuntimeError("anvil failed to start on http://localhost:8545")

    yield proc
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="session")
def settlement_service(anvil_proc):
    _ = anvil_proc
    escrow_address = _deploy_escrow()
    evm = EVMAdapter(
        rpc_url=RPC_URL,
        private_key=ANVIL_PK0,
        contract_address=escrow_address,
        chain_id=CHAIN_ID,
    )
    return SettlementService(evm)


def _task_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def test_create_set_worker_release_flow(settlement_service: SettlementService):
    task_id = _task_id("svc-flow")
    amount = 10**18
    deadline = int(time.time()) + 3600

    settlement_service.settle_create(task_id, amount, deadline)
    settlement_service.settle_set_worker(task_id, ANVIL_WORKER)
    settlement_service.settle_release(task_id)

    state = settlement_service.get_settlement_state(task_id)
    assert state.released is True
    assert state.refunded is False
    assert state.employer != "0x0000000000000000000000000000000000000000"


def test_fee_math(settlement_service: SettlementService):
    task_id = _task_id("svc-fee")
    amount = 10**18
    deadline = int(time.time()) + 3600

    settlement_service.settle_create(task_id, amount, deadline)
    settlement_service.settle_set_worker(task_id, ANVIL_WORKER)
    tx_hash = settlement_service.settle_release(task_id)

    receipt = settlement_service.evm.wait_receipt(tx_hash)
    events = settlement_service.evm.decode_events(receipt)
    released = next(ev for ev in events if ev["event"] == "Released")
    payout = released["args"]["payout"]
    fee = released["args"]["fee"]

    fee_bps = settlement_service.evm.get_fee_params()["feeBps"]
    expected_payout = amount * (10_000 - fee_bps) // 10_000
    expected_fee = amount - expected_payout
    assert payout == expected_payout
    assert fee == expected_fee


def test_revert_on_double_release(settlement_service: SettlementService):
    task_id = _task_id("svc-double-release")
    amount = 10**18
    deadline = int(time.time()) + 3600

    settlement_service.settle_create(task_id, amount, deadline)
    settlement_service.settle_set_worker(task_id, ANVIL_WORKER)
    settlement_service.settle_release(task_id)

    with pytest.raises(SettlementRevert):
        settlement_service.settle_release(task_id)


def test_invalid_deadline_range(settlement_service: SettlementService):
    task_id = _task_id("svc-deadline")
    amount = 1
    with pytest.raises(ValueError):
        settlement_service.settle_create(task_id, amount, 2**64)
