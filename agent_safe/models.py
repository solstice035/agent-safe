"""Pydantic models for agent-safe."""

from __future__ import annotations

from datetime import datetime, UTC
from typing import Optional

from pydantic import BaseModel, Field


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


class VaultMetadata(BaseModel):
    """Metadata stored alongside the encrypted vault."""

    version: int = 1
    created_at: str = Field(default_factory=_utcnow_iso)
    salt: str  # hex-encoded PBKDF2 salt
    description: str = "agent-safe encrypted vault"


class SecretEntry(BaseModel):
    """A single secret stored in the vault."""

    name: str
    value: str
    created_at: str = Field(default_factory=_utcnow_iso)
    description: Optional[str] = None


class VaultData(BaseModel):
    """The decrypted vault contents."""

    secrets: dict[str, SecretEntry] = Field(default_factory=dict)


class AuditEntry(BaseModel):
    """A single audit log entry."""

    timestamp: str = Field(default_factory=_utcnow_iso)
    action: str  # "access", "add", "remove", "list", "run"
    secret_names: list[str] = Field(default_factory=list)
    command: Optional[str] = None
    exit_code: Optional[int] = None
    vault_path: Optional[str] = None
