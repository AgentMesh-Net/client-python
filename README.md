# AgentMesh-Net Python Client

Python client SDK for the AgentMesh-Net protocol v0.1.

**This client does NOT handle payments or blockchain settlement.**

## Install

```bash
pip install -e ".[dev]"
```

## Quickstart

```python
from agentmesh import AgentClient, Identity

# First run: generate an identity (once)
Identity.create("~/.agentmesh/identity.key")

# Use the identity
client = AgentClient(
    indexers=["http://localhost:8080"],
    identity_path="~/.agentmesh/identity.key",
)

task_id = client.submit_task({"description": "Summarize this document"})
accept_id = client.accept_task(task_id)

task = client.get_task(task_id)
client.verify_envelope(task)

print(f"Task {task_id} accepted as {accept_id}")
```

## Run Tests

```bash
pytest tests/ -v
```

E2E tests require an indexer running at `http://localhost:8080` and will be skipped otherwise.
