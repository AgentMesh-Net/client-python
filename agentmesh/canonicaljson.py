"""RFC 8785 JSON Canonicalization Scheme (JCS) wrapper.

Delegates to the ``jcs`` library (a Python implementation of RFC 8785)
which matches the Go reference (cyberphone/json-canonicalization) byte-for-byte.
"""

import jcs as _jcs

from .errors import CanonicalizationError


def canonicalize(obj: dict) -> bytes:
    """Canonicalize a JSON-serializable dict to UTF-8 bytes per RFC 8785.

    Args:
        obj: A JSON-serializable dictionary.

    Returns:
        Canonical JSON encoded as UTF-8 bytes.

    Raises:
        CanonicalizationError: If the input cannot be canonicalized.
    """
    if not isinstance(obj, dict):
        raise CanonicalizationError("Input must be a JSON object (dict)")
    try:
        return _jcs.canonicalize(obj)
    except Exception as e:
        raise CanonicalizationError(f"Canonicalization failed: {e}") from e
