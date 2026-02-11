"""Envelope construction, signing, and verification per signed-envelope-v0.1."""

import base64
import re
import uuid
from datetime import datetime, timezone

from .canonicaljson import canonicalize
from .identity import Identity
from .errors import EnvelopeError, SignatureError

VALID_OBJECT_TYPES = frozenset({"task", "bid", "accept", "artifact"})
OBJECT_VERSION = "0.1"
_BASE64_STANDARD_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")


def _validate_base64_standard(value: str, field_name: str) -> bytes:
    """Decode and validate standard base64 (RFC 4648 §4). Rejects URL-safe."""
    if not isinstance(value, str):
        raise EnvelopeError(f"{field_name} must be a string")
    if "-" in value or "_" in value:
        raise EnvelopeError(
            f"{field_name} uses URL-safe base64; standard base64 required"
        )
    if not _BASE64_STANDARD_RE.match(value):
        raise EnvelopeError(f"{field_name} is not valid base64")
    try:
        return base64.b64decode(value)
    except Exception as e:
        raise EnvelopeError(f"{field_name} base64 decode failed: {e}") from e


def validate_envelope_structure(envelope: dict) -> None:
    """Validate all envelope fields per spec §3.1.

    Raises:
        EnvelopeError: On any structural violation.
    """
    required = {
        "object_type", "object_version", "object_id",
        "created_at", "payload", "signer", "signature",
    }
    missing = required - set(envelope.keys())
    if missing:
        raise EnvelopeError(f"Missing envelope fields: {missing}")

    if envelope["object_type"] not in VALID_OBJECT_TYPES:
        raise EnvelopeError(f"Invalid object_type: {envelope['object_type']}")

    if envelope["object_version"] != OBJECT_VERSION:
        raise EnvelopeError(
            f"Unsupported object_version: {envelope['object_version']}"
        )

    if not isinstance(envelope["object_id"], str) or not envelope["object_id"]:
        raise EnvelopeError("object_id must be a non-empty string")

    if not isinstance(envelope["created_at"], str):
        raise EnvelopeError("created_at must be a string")
    try:
        datetime.fromisoformat(envelope["created_at"])
    except ValueError as e:
        raise EnvelopeError(f"Invalid RFC3339 timestamp: {e}") from e

    if not isinstance(envelope["payload"], dict):
        raise EnvelopeError("payload must be a JSON object")

    signer = envelope.get("signer")
    if not isinstance(signer, dict):
        raise EnvelopeError("signer must be an object")
    if signer.get("algo") != "ed25519":
        raise EnvelopeError(
            f"Unsupported signer algorithm: {signer.get('algo')}"
        )

    pubkey_bytes = _validate_base64_standard(
        signer.get("pubkey", ""), "signer.pubkey"
    )
    if len(pubkey_bytes) != 32:
        raise EnvelopeError(
            f"signer.pubkey must decode to 32 bytes, got {len(pubkey_bytes)}"
        )

    sig_bytes = _validate_base64_standard(envelope["signature"], "signature")
    if len(sig_bytes) != 64:
        raise EnvelopeError(
            f"signature must decode to 64 bytes, got {len(sig_bytes)}"
        )


def build_preimage(envelope: dict) -> bytes:
    """Build signing preimage: envelope without 'signature', canonicalized."""
    without_sig = {k: v for k, v in envelope.items() if k != "signature"}
    return canonicalize(without_sig)


def build_envelope(
    object_type: str,
    payload: dict,
    identity: Identity,
    object_id: str | None = None,
) -> dict:
    """Build and sign a new envelope.

    Args:
        object_type: One of task, bid, accept, artifact.
        payload: The payload dict.
        identity: Signing identity.
        object_id: Optional explicit object_id; UUID4 generated if omitted.

    Returns:
        A complete signed envelope dict.
    """
    if object_type not in VALID_OBJECT_TYPES:
        raise EnvelopeError(f"Invalid object_type: {object_type}")

    envelope = {
        "object_type": object_type,
        "object_version": OBJECT_VERSION,
        "object_id": object_id or str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "payload": payload,
        "signer": {
            "algo": "ed25519",
            "pubkey": identity.public_key_base64,
        },
    }

    preimage = canonicalize(envelope)
    sig = identity.sign(preimage)
    envelope["signature"] = base64.b64encode(sig).decode("ascii")
    return envelope


def verify_envelope(envelope: dict) -> None:
    """Verify envelope structure and ed25519 signature.

    Raises:
        EnvelopeError: On structural violations.
        SignatureError: On signature verification failure.
    """
    validate_envelope_structure(envelope)

    preimage = build_preimage(envelope)
    pubkey_bytes = base64.b64decode(envelope["signer"]["pubkey"])
    sig_bytes = base64.b64decode(envelope["signature"])

    Identity.verify(pubkey_bytes, sig_bytes, preimage)
