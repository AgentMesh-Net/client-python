"""Machine-readable error categories for AgentMesh-Net protocol failures."""


class AgentMeshError(Exception):
    """Base exception for all AgentMesh errors."""


class EnvelopeError(AgentMeshError):
    """Invalid envelope structure or schema."""


class SignatureError(AgentMeshError):
    """Signature verification failed."""


class CanonicalizationError(AgentMeshError):
    """JSON canonicalization failed."""


class IdentityError(AgentMeshError):
    """Identity key loading or generation error."""


class IndexerError(AgentMeshError):
    """Indexer transport or API error."""


class AcceptRuleError(AgentMeshError):
    """Accept validation rule violation (missing task_id or signer mismatch)."""
