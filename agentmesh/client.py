"""High-level AgentMesh-Net client for interacting with indexers."""

import requests

from .envelope import build_envelope, verify_envelope
from .identity import Identity
from .errors import IndexerError, AcceptRuleError, EnvelopeError, IdentityError


class AgentClient:
    """Client for submitting and fetching AgentMesh-Net protocol objects.

    Manages an ed25519 identity and communicates with one or more indexers.
    """

    def __init__(self, indexers: list[str], identity_path: str):
        """Initialize client with indexer URLs and an existing identity key.

        The identity file must already exist.  Use ``Identity.create(path)``
        to generate one before constructing the client.

        Args:
            indexers: List of indexer base URLs (first is primary for writes).
            identity_path: Path to an existing ed25519 private key (32 bytes).

        Raises:
            IdentityError: If the identity file is missing or corrupt.
        """
        if not indexers:
            raise IndexerError("At least one indexer URL is required")
        self._indexers = [url.rstrip("/") for url in indexers]
        self._identity = Identity.load(identity_path)

    @property
    def _primary(self) -> str:
        return self._indexers[0]

    @property
    def public_key(self) -> str:
        """Base64-encoded ed25519 public key of this client's identity."""
        return self._identity.public_key_base64

    def submit_task(self, payload: dict) -> str:
        """Create, sign, and submit a task envelope.

        Returns:
            The task's object_id.
        """
        envelope = build_envelope("task", payload, self._identity)
        self._post("/v1/tasks", envelope)
        return envelope["object_id"]

    def accept_task(self, task_id: str) -> str:
        """Create, sign, and submit an accept envelope for a task.

        Enforces: accept signer must equal task signer.
        Enforces: payload.task_id must equal the task's object_id.

        Returns:
            The accept's object_id.
        """
        task = self.get_task(task_id)
        if task["signer"]["pubkey"] != self._identity.public_key_base64:
            raise AcceptRuleError("Accept signer must equal task signer")

        payload = {"task_id": task_id}
        envelope = build_envelope("accept", payload, self._identity)
        self._post("/v1/accepts", envelope)
        return envelope["object_id"]

    def submit_object(self, envelope: dict) -> str:
        """Submit a pre-built envelope to the correct endpoint.

        Returns:
            The object_id.
        """
        endpoint_map = {
            "task": "/v1/tasks",
            "bid": "/v1/bids",
            "accept": "/v1/accepts",
            "artifact": "/v1/artifacts",
        }
        object_type = envelope.get("object_type")
        endpoint = endpoint_map.get(object_type)
        if not endpoint:
            raise EnvelopeError(f"Unknown object_type: {object_type}")
        self._post(endpoint, envelope)
        return envelope["object_id"]

    def get_task(self, task_id: str) -> dict:
        """Fetch a task by object_id. Verifies signature locally.

        Returns:
            The verified task envelope dict.
        """
        return self._find_object("/v1/tasks", task_id)

    def get_accept(self, accept_id: str) -> dict:
        """Fetch an accept by object_id. Verifies signature locally.

        Returns:
            The verified accept envelope dict.
        """
        return self._find_object("/v1/accepts", accept_id)

    def verify_envelope(self, envelope: dict) -> None:
        """Verify envelope structure and signature locally.

        Raises:
            EnvelopeError: On structural violations.
            SignatureError: On signature verification failure.
        """
        verify_envelope(envelope)

    # -- internal helpers --

    def _post(self, path: str, data: dict) -> dict:
        url = f"{self._primary}{path}"
        try:
            resp = requests.post(url, json=data, timeout=30)
        except requests.RequestException as e:
            raise IndexerError(f"POST {url} failed: {e}") from e

        if resp.status_code in (200, 201):
            return resp.json()
        if resp.status_code == 409:
            raise IndexerError("Conflict: object_id already exists")

        try:
            msg = resp.json().get("error", {}).get("message", resp.text)
        except Exception:
            msg = resp.text
        raise IndexerError(
            f"Indexer rejected request ({resp.status_code}): {msg}"
        )

    def _find_object(self, path: str, object_id: str) -> dict:
        """Paginate through indexer list results to find an object by id."""
        for indexer in self._indexers:
            cursor = None
            while True:
                url = f"{indexer}{path}"
                params: dict = {"limit": "200"}
                if cursor:
                    params["cursor"] = cursor
                try:
                    resp = requests.get(url, params=params, timeout=30)
                except requests.RequestException as e:
                    raise IndexerError(f"GET {url} failed: {e}") from e

                if resp.status_code != 200:
                    raise IndexerError(
                        f"Indexer error ({resp.status_code}): {resp.text}"
                    )

                data = resp.json()
                for item in data.get("items", []):
                    if item.get("object_id") == object_id:
                        verify_envelope(item)
                        return item

                next_cursor = data.get("next_cursor")
                if not next_cursor:
                    break
                cursor = next_cursor

        raise IndexerError(f"Object not found: {object_id}")
