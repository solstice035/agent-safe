"""Append-only JSONL audit logging for secret access."""

from __future__ import annotations

from pathlib import Path

from .models import AuditEntry

DEFAULT_AUDIT_FILE = Path.home() / ".agent-safe" / "audit.jsonl"


def get_audit_path(vault_path: str | Path | None = None) -> Path:
    """Get the audit log file path."""
    if vault_path:
        return Path(vault_path) / "audit.jsonl"
    return DEFAULT_AUDIT_FILE


def log_access(
    action: str,
    secret_names: list[str] | None = None,
    command: str | None = None,
    exit_code: int | None = None,
    vault_path: str | Path | None = None,
) -> AuditEntry:
    """Append an audit entry to the log."""
    audit_path = get_audit_path(vault_path)
    audit_path.parent.mkdir(parents=True, exist_ok=True)

    entry = AuditEntry(
        action=action,
        secret_names=secret_names or [],
        command=command,
        exit_code=exit_code,
        vault_path=str(vault_path) if vault_path else None,
    )

    with open(audit_path, "a") as f:
        f.write(entry.model_dump_json() + "\n")

    return entry


def read_audit_log(
    vault_path: str | Path | None = None, last_n: int | None = None
) -> list[AuditEntry]:
    """Read audit log entries."""
    audit_path = get_audit_path(vault_path)
    if not audit_path.exists():
        return []

    entries = []
    for line in audit_path.read_text().splitlines():
        line = line.strip()
        if line:
            entries.append(AuditEntry.model_validate_json(line))

    if last_n is not None:
        entries = entries[-last_n:]

    return entries
