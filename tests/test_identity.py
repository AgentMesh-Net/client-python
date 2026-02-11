"""Tests for ed25519 identity management."""

import base64
import os
import tempfile

import pytest

from agentmesh.identity import Identity
from agentmesh.errors import IdentityError, SignatureError


class TestIdentityGenerate:
    def test_generate_produces_valid_key(self):
        ident = Identity.generate()
        assert len(ident.public_key_bytes) == 32

    def test_public_key_base64_is_standard(self):
        ident = Identity.generate()
        pk = ident.public_key_base64
        # Must be standard base64 (no - or _)
        assert "-" not in pk
        assert "_" not in pk
        # Must decode to 32 bytes
        assert len(base64.b64decode(pk)) == 32

    def test_two_identities_differ(self):
        a = Identity.generate()
        b = Identity.generate()
        assert a.public_key_bytes != b.public_key_bytes


class TestIdentitySaveLoad:
    def test_round_trip(self, tmp_path):
        path = str(tmp_path / "key")
        orig = Identity.generate()
        orig.save(path)
        loaded = Identity.load(path)
        assert loaded.public_key_bytes == orig.public_key_bytes

    def test_save_creates_parent_dirs(self, tmp_path):
        path = str(tmp_path / "a" / "b" / "c" / "key")
        ident = Identity.generate()
        ident.save(path)
        loaded = Identity.load(path)
        assert loaded.public_key_bytes == ident.public_key_bytes

    def test_load_missing_file_raises(self):
        with pytest.raises(IdentityError, match="not found"):
            Identity.load("/nonexistent/path/key")

    def test_load_wrong_length_raises(self, tmp_path):
        path = str(tmp_path / "badkey")
        with open(path, "wb") as f:
            f.write(b"too short")
        with pytest.raises(IdentityError, match="expected 32 bytes"):
            Identity.load(path)


class TestIdentityCreate:
    def test_create_generates_and_saves(self, tmp_path):
        path = str(tmp_path / "new.key")
        ident = Identity.create(path)
        assert len(ident.public_key_bytes) == 32
        loaded = Identity.load(path)
        assert loaded.public_key_bytes == ident.public_key_bytes

    def test_create_makes_parent_dirs(self, tmp_path):
        path = str(tmp_path / "deep" / "dir" / "key")
        ident = Identity.create(path)
        assert Identity.load(path).public_key_bytes == ident.public_key_bytes

    def test_create_refuses_overwrite(self, tmp_path):
        path = str(tmp_path / "existing.key")
        Identity.create(path)
        with pytest.raises(IdentityError, match="already exists"):
            Identity.create(path)


class TestIdentitySignVerify:
    def test_sign_and_verify(self):
        ident = Identity.generate()
        msg = b"hello world"
        sig = ident.sign(msg)
        assert len(sig) == 64
        # Should not raise
        Identity.verify(ident.public_key_bytes, sig, msg)

    def test_verify_wrong_message_fails(self):
        ident = Identity.generate()
        sig = ident.sign(b"correct message")
        with pytest.raises(SignatureError):
            Identity.verify(ident.public_key_bytes, sig, b"wrong message")

    def test_verify_wrong_key_fails(self):
        a = Identity.generate()
        b = Identity.generate()
        sig = a.sign(b"message")
        with pytest.raises(SignatureError):
            Identity.verify(b.public_key_bytes, sig, b"message")

    def test_verify_tampered_signature_fails(self):
        ident = Identity.generate()
        sig = bytearray(ident.sign(b"message"))
        sig[0] ^= 0xFF  # flip a byte
        with pytest.raises(SignatureError):
            Identity.verify(ident.public_key_bytes, bytes(sig), b"message")
