"""Typed dictionaries for AgentMesh-Net protocol objects."""

from typing import Any, TypedDict


class Signer(TypedDict):
    algo: str
    pubkey: str


class Envelope(TypedDict):
    object_type: str
    object_version: str
    object_id: str
    created_at: str
    payload: dict[str, Any]
    signer: Signer
    signature: str


class AcceptPayload(TypedDict):
    task_id: str
