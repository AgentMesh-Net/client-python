"""End-to-end tests against a live indexer.

These tests assume an AgentMesh-Net indexer is running at http://localhost:8080.
Skip with: pytest -m "not e2e"
"""

import tempfile

import pytest
import requests

from agentmesh import AgentClient, Identity

INDEXER_URL = "http://localhost:8080"


def indexer_available() -> bool:
    try:
        resp = requests.get(f"{INDEXER_URL}/v1/indexer/info", timeout=3)
        return resp.status_code == 200
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not indexer_available(), reason="Indexer not running at localhost:8080"
)


@pytest.fixture
def client(tmp_path):
    key_path = str(tmp_path / "test_identity.key")
    Identity.create(key_path)
    return AgentClient(indexers=[INDEXER_URL], identity_path=key_path)


class TestE2EFlow:
    """Submit task -> submit accept -> fetch both -> verify locally."""

    def test_full_flow(self, client):
        # 1. Submit a task
        task_id = client.submit_task({"description": "e2e test task"})
        assert task_id

        # 2. Submit an accept referencing that task
        accept_id = client.accept_task(task_id)
        assert accept_id

        # 3. Fetch the task and verify
        task = client.get_task(task_id)
        assert task["object_id"] == task_id
        assert task["object_type"] == "task"
        assert task["payload"]["description"] == "e2e test task"
        client.verify_envelope(task)

        # 4. Fetch the accept and verify
        accept = client.get_accept(accept_id)
        assert accept["object_id"] == accept_id
        assert accept["object_type"] == "accept"
        assert accept["payload"]["task_id"] == task_id
        client.verify_envelope(accept)

        # 5. Verify signer match
        assert task["signer"]["pubkey"] == accept["signer"]["pubkey"]

    def test_submit_task_returns_unique_ids(self, client):
        id1 = client.submit_task({"desc": "task 1"})
        id2 = client.submit_task({"desc": "task 2"})
        assert id1 != id2

    def test_indexer_info(self):
        resp = requests.get(f"{INDEXER_URL}/v1/indexer/info", timeout=5)
        assert resp.status_code == 200
        info = resp.json()
        assert "version" in info or "capabilities" in info
