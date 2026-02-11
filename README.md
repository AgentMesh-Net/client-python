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

## Optional: EVM Settlement

An optional adapter lets you interact with the **AgentMeshEscrow** contract
(`settlement-evm-v0.2.0`) on any EVM chain.  It is fully decoupled from the
core protocol modules.

### Install

```bash
pip install -e ".[evm]"
```

### Configuration

| Variable | Required | Default |
|---|---|---|
| `AMN_EVM_RPC_URL` | no | `http://localhost:8545` |
| `AMN_EVM_PRIVATE_KEY` | **yes** | – |
| `AMN_ESCROW_ADDRESS` | **yes** | – |
| `AMN_EVM_CHAIN_ID` | no | `31337` |
| `AMN_EVM_TIMEOUT` | no | `30` |

### Usage

```python
from agentmesh.settlement.evm import EvmEscrowClient, task_hash

client = EvmEscrowClient()  # reads env vars
tx = client.create_escrow("my-task", amount_wei=10**18, deadline_unix=1700000000)
receipt = client.wait_receipt(tx)
print(client.decode_events(receipt))
```

### Local demo (Anvil)

1. Start Anvil: `anvil`
2. Deploy the contract and note the address.
3. Run the demo:

```bash
export AMN_EVM_PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
export AMN_ESCROW_ADDRESS="<deployed address>"
python scripts/demo_evm_local.py [task_id]
```

The script will create an escrow, assign a worker, release funds, and verify
that the 20 bps fee matches expectations.
