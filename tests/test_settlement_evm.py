"""Unit tests for agentmesh.settlement.evm helpers.

These tests do NOT require a running chain – they exercise pure
functions only (task_hash).
"""

import shutil
import subprocess
import time
from pathlib import Path

import pytest

# These imports will fail if the evm extras are not installed.
# Mark the whole module so pytest skips cleanly in that case.
pytestmark = pytest.mark.skipif(
    not __import__("importlib").util.find_spec("eth_utils"),
    reason="evm extras not installed (pip install -e '.[evm]')",
)


def test_task_hash_known_vector():
    """keccak256(b"demo-task-001") should match the eth_utils reference."""
    from eth_utils import keccak

    from agentmesh.settlement.evm import task_hash

    expected = keccak(b"demo-task-001")
    assert task_hash("demo-task-001") == expected


def test_task_hash_is_32_bytes():
    from agentmesh.settlement.evm import task_hash

    h = task_hash("anything")
    assert isinstance(h, bytes)
    assert len(h) == 32


def test_task_hash_deterministic():
    from agentmesh.settlement.evm import task_hash

    assert task_hash("x") == task_hash("x")


def test_task_hash_different_inputs():
    from agentmesh.settlement.evm import task_hash

    assert task_hash("a") != task_hash("b")


def test_evm_create_settlement_smoke():
    """Run local EVM demo smoke script and assert PASS."""
    if shutil.which("cast") is None or shutil.which("jq") is None:
        pytest.skip("requires cast and jq in PATH")

    # Skip when local Anvil/Hardhat JSON-RPC is not available.
    rpc_probe = subprocess.run(
        [
            "curl",
            "-s",
            "-X",
            "POST",
            "http://localhost:8545",
            "-H",
            "content-type: application/json",
            "--data",
            '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}',
        ],
        capture_output=True,
        text=True,
    )
    if rpc_probe.returncode != 0 or "result" not in (rpc_probe.stdout or ""):
        pytest.skip("local RPC http://localhost:8545 is not available")

    repo_root = Path(__file__).resolve().parents[1]
    smoke = repo_root / "scripts" / "smoke_evm_local.sh"
    assert smoke.exists(), f"missing smoke script: {smoke}"

    proc = subprocess.run(
        [str(smoke), f"pytest-smoke-evm-{int(time.time())}"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        timeout=180,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    assert proc.returncode == 0, output
    assert "[smoke][PASS]" in output, output
