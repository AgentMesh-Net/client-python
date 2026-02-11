"""Unit tests for agentmesh.settlement.evm helpers.

These tests do NOT require a running chain – they exercise pure
functions only (task_hash).
"""

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
