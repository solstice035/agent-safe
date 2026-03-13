"""Tests for the audit module."""

import pytest

from agent_safe.audit import log_access, read_audit_log


@pytest.fixture
def audit_dir(tmp_path):
    return tmp_path / "audit-vault"


class TestAuditLog:
    def test_log_creates_file(self, audit_dir):
        log_access("test_action", vault_path=str(audit_dir))
        assert (audit_dir / "audit.jsonl").exists()

    def test_log_is_append_only(self, audit_dir):
        log_access("action1", secret_names=["KEY1"], vault_path=str(audit_dir))
        log_access("action2", secret_names=["KEY2"], vault_path=str(audit_dir))

        entries = read_audit_log(vault_path=str(audit_dir))
        assert len(entries) == 2
        assert entries[0].action == "action1"
        assert entries[1].action == "action2"

    def test_log_captures_command(self, audit_dir):
        log_access(
            "run",
            secret_names=["API_KEY"],
            command="claude-code task.md",
            vault_path=str(audit_dir),
        )
        entries = read_audit_log(vault_path=str(audit_dir))
        assert entries[0].command == "claude-code task.md"
        assert entries[0].secret_names == ["API_KEY"]

    def test_log_captures_exit_code(self, audit_dir):
        log_access("run_complete", exit_code=0, vault_path=str(audit_dir))
        entries = read_audit_log(vault_path=str(audit_dir))
        assert entries[0].exit_code == 0

    def test_read_last_n(self, audit_dir):
        for i in range(10):
            log_access(f"action_{i}", vault_path=str(audit_dir))

        entries = read_audit_log(vault_path=str(audit_dir), last_n=3)
        assert len(entries) == 3
        assert entries[0].action == "action_7"

    def test_read_empty_log(self, audit_dir):
        entries = read_audit_log(vault_path=str(audit_dir))
        assert entries == []

    def test_entry_has_timestamp(self, audit_dir):
        entry = log_access("test", vault_path=str(audit_dir))
        assert entry.timestamp is not None
        assert "T" in entry.timestamp  # ISO format
