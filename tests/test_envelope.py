"""Tests for envelope building, signing, verification, and canonicalization."""

import base64
import copy

import pytest

from agentmesh.identity import Identity
from agentmesh.envelope import build_envelope, verify_envelope, validate_envelope_structure
from agentmesh.canonicaljson import canonicalize
from agentmesh.errors import EnvelopeError, SignatureError


class TestCanonicalization:
    """RFC 8785 test vectors from the spec."""

    def test_object_member_ordering(self):
        result = canonicalize({"b": 2, "a": 1})
        assert result == b'{"a":1,"b":2}'

    def test_whitespace_removal(self):
        result = canonicalize(
            {"z": [3, 2, 1], "a": {"y": True, "x": False}}
        )
        assert result == b'{"a":{"x":false,"y":true},"z":[3,2,1]}'

    def test_number_canonicalization(self):
        # Integer-valued floats should serialize as integers
        result = canonicalize({"n1": 1, "n4": 0})
        assert result == b'{"n1":1,"n4":0}'

    def test_nested_key_sorting(self):
        result = canonicalize({"c": {"z": 1, "a": 2}, "a": 1})
        assert result == b'{"a":1,"c":{"a":2,"z":1}}'


class TestBuildEnvelope:
    def test_builds_valid_envelope(self):
        ident = Identity.generate()
        env = build_envelope("task", {"desc": "test"}, ident)

        assert env["object_type"] == "task"
        assert env["object_version"] == "0.1"
        assert env["object_id"]  # non-empty
        assert env["created_at"]  # non-empty
        assert env["payload"] == {"desc": "test"}
        assert env["signer"]["algo"] == "ed25519"
        assert env["signer"]["pubkey"] == ident.public_key_base64
        assert "signature" in env

    def test_object_id_is_uuid(self):
        ident = Identity.generate()
        env = build_envelope("task", {}, ident)
        # UUID4 format
        assert len(env["object_id"]) == 36
        assert env["object_id"].count("-") == 4

    def test_custom_object_id(self):
        ident = Identity.generate()
        env = build_envelope("task", {}, ident, object_id="custom-id-123")
        assert env["object_id"] == "custom-id-123"

    def test_invalid_object_type_rejected(self):
        ident = Identity.generate()
        with pytest.raises(EnvelopeError, match="Invalid object_type"):
            build_envelope("invalid", {}, ident)

    def test_all_object_types(self):
        ident = Identity.generate()
        for otype in ("task", "bid", "accept", "artifact"):
            env = build_envelope(otype, {}, ident)
            assert env["object_type"] == otype

    def test_signature_is_standard_base64(self):
        ident = Identity.generate()
        env = build_envelope("task", {}, ident)
        sig = env["signature"]
        assert "-" not in sig
        assert "_" not in sig
        assert len(base64.b64decode(sig)) == 64


class TestVerifyEnvelope:
    def test_valid_envelope_passes(self):
        ident = Identity.generate()
        env = build_envelope("task", {"hello": "world"}, ident)
        # Should not raise
        verify_envelope(env)

    def test_tampered_payload_fails(self):
        ident = Identity.generate()
        env = build_envelope("task", {"amount": 100}, ident)
        env["payload"]["amount"] = 999  # tamper
        with pytest.raises(SignatureError):
            verify_envelope(env)

    def test_tampered_object_id_fails(self):
        ident = Identity.generate()
        env = build_envelope("task", {}, ident)
        env["object_id"] = "tampered-id"
        with pytest.raises(SignatureError):
            verify_envelope(env)

    def test_tampered_signer_pubkey_fails(self):
        a = Identity.generate()
        b = Identity.generate()
        env = build_envelope("task", {}, a)
        env["signer"]["pubkey"] = b.public_key_base64
        with pytest.raises(SignatureError):
            verify_envelope(env)

    def test_missing_signature_field(self):
        ident = Identity.generate()
        env = build_envelope("task", {}, ident)
        del env["signature"]
        with pytest.raises(EnvelopeError, match="Missing"):
            verify_envelope(env)

    def test_missing_payload_field(self):
        ident = Identity.generate()
        env = build_envelope("task", {}, ident)
        del env["payload"]
        with pytest.raises(EnvelopeError, match="Missing"):
            verify_envelope(env)

    def test_wrong_object_version(self):
        ident = Identity.generate()
        env = build_envelope("task", {}, ident)
        env["object_version"] = "0.2"
        with pytest.raises(EnvelopeError, match="Unsupported object_version"):
            verify_envelope(env)

    def test_wrong_algo(self):
        ident = Identity.generate()
        env = build_envelope("task", {}, ident)
        env["signer"]["algo"] = "rsa"
        with pytest.raises(EnvelopeError, match="Unsupported signer algorithm"):
            verify_envelope(env)

    def test_url_safe_base64_rejected_in_pubkey(self):
        ident = Identity.generate()
        env = build_envelope("task", {}, ident)
        # Replace + with - to make it URL-safe
        env["signer"]["pubkey"] = env["signer"]["pubkey"].replace(
            "A", "-"
        ) if "A" in env["signer"]["pubkey"] else "-" + env["signer"]["pubkey"][1:]
        with pytest.raises(EnvelopeError, match="URL-safe"):
            verify_envelope(env)

    def test_url_safe_base64_rejected_in_signature(self):
        ident = Identity.generate()
        env = build_envelope("task", {}, ident)
        # Force URL-safe character into signature
        env["signature"] = "_" + env["signature"][1:]
        with pytest.raises(EnvelopeError, match="URL-safe"):
            verify_envelope(env)

    def test_empty_object_id_rejected(self):
        ident = Identity.generate()
        env = build_envelope("task", {}, ident)
        env["object_id"] = ""
        with pytest.raises(EnvelopeError, match="non-empty"):
            verify_envelope(env)


class TestSignatureDeterminism:
    def test_canonicalization_deterministic(self):
        """Same input must always produce same canonical bytes."""
        data = {"z": 1, "a": {"c": 3, "b": 2}}
        assert canonicalize(data) == canonicalize(data)

    def test_key_order_irrelevant(self):
        """Different key insertion order produces same canonical output."""
        from collections import OrderedDict

        a = OrderedDict([("z", 1), ("a", 2)])
        b = OrderedDict([("a", 2), ("z", 1)])
        assert canonicalize(dict(a)) == canonicalize(dict(b))
