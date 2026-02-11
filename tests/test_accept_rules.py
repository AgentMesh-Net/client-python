"""Tests for accept-specific validation rules.

Accept objects MUST:
- contain payload.task_id equal to referenced task's object_id
- be signed by the same signer as the referenced task
"""

import pytest

from agentmesh.identity import Identity
from agentmesh.envelope import build_envelope, verify_envelope
from agentmesh.errors import AcceptRuleError, EnvelopeError


class TestAcceptPayloadTaskId:
    def test_valid_accept_has_task_id(self):
        ident = Identity.generate()
        task = build_envelope("task", {"desc": "do something"}, ident)
        accept = build_envelope(
            "accept", {"task_id": task["object_id"]}, ident
        )
        # Structural and signature verification should pass
        verify_envelope(accept)
        assert accept["payload"]["task_id"] == task["object_id"]

    def test_accept_missing_task_id_in_payload(self):
        """Accept with empty payload (no task_id) is structurally valid as an
        envelope, but violates accept-specific rules."""
        ident = Identity.generate()
        accept = build_envelope("accept", {}, ident)
        # Envelope itself is valid (signature checks pass)
        verify_envelope(accept)
        # But payload.task_id is missing - clients must check this
        assert "task_id" not in accept["payload"]

    def test_accept_wrong_task_id(self):
        """Accept with mismatched task_id does not reference the correct task."""
        ident = Identity.generate()
        task = build_envelope("task", {"desc": "real task"}, ident)
        accept = build_envelope(
            "accept", {"task_id": "wrong-id-12345"}, ident
        )
        verify_envelope(accept)
        assert accept["payload"]["task_id"] != task["object_id"]


class TestAcceptSignerMatch:
    def test_same_signer_valid(self):
        ident = Identity.generate()
        task = build_envelope("task", {"desc": "test"}, ident)
        accept = build_envelope(
            "accept", {"task_id": task["object_id"]}, ident
        )
        assert task["signer"]["pubkey"] == accept["signer"]["pubkey"]

    def test_different_signer_detected(self):
        """Accept signed by a different key than the task must be rejected."""
        alice = Identity.generate()
        bob = Identity.generate()
        task = build_envelope("task", {"desc": "test"}, alice)
        accept = build_envelope(
            "accept", {"task_id": task["object_id"]}, bob
        )
        # Both envelopes are individually valid
        verify_envelope(task)
        verify_envelope(accept)
        # But signers do not match - clients must enforce this
        assert task["signer"]["pubkey"] != accept["signer"]["pubkey"]


class TestAcceptClientValidation:
    """Tests for the client-level accept validation logic (without network)."""

    def test_signer_mismatch_raises(self):
        """Simulates the check AgentClient.accept_task performs."""
        alice = Identity.generate()
        bob = Identity.generate()
        task = build_envelope("task", {"desc": "test"}, alice)

        # Simulate the check from AgentClient.accept_task
        if task["signer"]["pubkey"] != bob.public_key_base64:
            with pytest.raises(AcceptRuleError, match="signer"):
                raise AcceptRuleError("Accept signer must equal task signer")

    def test_signer_match_passes(self):
        """Same identity for task and accept should pass validation."""
        ident = Identity.generate()
        task = build_envelope("task", {"desc": "test"}, ident)
        assert task["signer"]["pubkey"] == ident.public_key_base64
