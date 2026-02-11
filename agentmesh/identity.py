"""Ed25519 identity management: key generation, load, save, sign, verify."""

import base64
from pathlib import Path

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

from .errors import IdentityError, SignatureError


class Identity:
    """An ed25519 signing identity backed by a private key."""

    def __init__(self, signing_key: SigningKey):
        self._signing_key = signing_key

    @classmethod
    def generate(cls) -> "Identity":
        """Generate a new random ed25519 keypair (in-memory only)."""
        return cls(SigningKey.generate())

    @classmethod
    def create(cls, path: str) -> "Identity":
        """Generate a new keypair and save it to *path*. Creates parent dirs.

        Raises:
            IdentityError: If *path* already exists (will not overwrite).
        """
        p = Path(path)
        if p.exists():
            raise IdentityError(f"Identity file already exists: {path}")
        identity = cls.generate()
        identity.save(path)
        return identity

    @classmethod
    def load(cls, path: str) -> "Identity":
        """Load an ed25519 private key from a file (raw 32 bytes)."""
        p = Path(path)
        if not p.exists():
            raise IdentityError(f"Identity file not found: {path}")
        raw = p.read_bytes()
        if len(raw) != 32:
            raise IdentityError(
                f"Invalid key file: expected 32 bytes, got {len(raw)}"
            )
        return cls(SigningKey(raw))

    def save(self, path: str) -> None:
        """Save the raw 32-byte private key to disk. Creates parent dirs."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(bytes(self._signing_key))

    @property
    def public_key_bytes(self) -> bytes:
        """Raw 32-byte ed25519 public key."""
        return bytes(self._signing_key.verify_key)

    @property
    def public_key_base64(self) -> str:
        """Base64-encoded public key (RFC 4648 §4 with padding)."""
        return base64.b64encode(self.public_key_bytes).decode("ascii")

    def sign(self, message: bytes) -> bytes:
        """Sign message bytes, returning 64-byte ed25519 signature."""
        signed = self._signing_key.sign(message)
        return signed.signature

    @staticmethod
    def verify(pubkey_bytes: bytes, signature: bytes, message: bytes) -> None:
        """Verify an ed25519 signature over message bytes.

        Raises:
            SignatureError: If verification fails.
        """
        try:
            vk = VerifyKey(pubkey_bytes)
            vk.verify(message, signature)
        except BadSignatureError as e:
            raise SignatureError(f"Signature verification failed: {e}") from e
        except Exception as e:
            raise SignatureError(f"Verification error: {e}") from e
