"""Tests for the command runner."""

import pytest

from agent_safe.vault import init_vault, add_secret
from agent_safe.runner import run_with_secrets
from agent_safe.audit import read_audit_log


@pytest.fixture
def vault_with_secrets(tmp_path):
    """Create a vault with test secrets."""
    vault_path = tmp_path / "test-vault"
    init_vault("testpass", vault_path=vault_path)
    add_secret("testpass", "MY_API_KEY", "sk-test-12345", vault_path=vault_path)
    add_secret("testpass", "DB_URL", "postgres://test:5432", vault_path=vault_path)
    return vault_path


class TestRunner:
    def test_run_injects_secrets(self, vault_with_secrets):
        """Verify secrets are available inside the subprocess."""
        exit_code = run_with_secrets(
            "testpass",
            command=["python3", "-c", "import os; assert os.environ.get('MY_API_KEY') == 'sk-test-12345'"],
            vault_path=str(vault_with_secrets),
        )
        assert exit_code == 0

    def test_run_specific_secrets(self, vault_with_secrets):
        """Only inject specified secrets."""
        exit_code = run_with_secrets(
            "testpass",
            command=[
                "python3", "-c",
                "import os; "
                "assert os.environ.get('MY_API_KEY') == 'sk-test-12345'; "
                "assert os.environ.get('DB_URL') is None",
            ],
            secret_names=["MY_API_KEY"],
            vault_path=str(vault_with_secrets),
        )
        assert exit_code == 0

    def test_run_all_secrets(self, vault_with_secrets):
        """Inject all secrets when none specified."""
        exit_code = run_with_secrets(
            "testpass",
            command=[
                "python3", "-c",
                "import os; "
                "assert os.environ.get('MY_API_KEY') == 'sk-test-12345'; "
                "assert os.environ.get('DB_URL') == 'postgres://test:5432'",
            ],
            vault_path=str(vault_with_secrets),
        )
        assert exit_code == 0

    def test_run_creates_audit_entries(self, vault_with_secrets):
        """Verify audit log is created for run commands."""
        run_with_secrets(
            "testpass",
            command=["echo", "hello"],
            vault_path=str(vault_with_secrets),
        )
        entries = read_audit_log(vault_path=str(vault_with_secrets))
        assert len(entries) >= 2  # run + run_complete
        actions = [e.action for e in entries]
        assert "run" in actions
        assert "run_complete" in actions

    def test_run_nonexistent_command(self, vault_with_secrets):
        """Handle command not found gracefully."""
        exit_code = run_with_secrets(
            "testpass",
            command=["nonexistent-command-xyz"],
            vault_path=str(vault_with_secrets),
        )
        assert exit_code == 127

    def test_run_failing_command(self, vault_with_secrets):
        """Capture non-zero exit codes."""
        exit_code = run_with_secrets(
            "testpass",
            command=["python3", "-c", "import sys; sys.exit(42)"],
            vault_path=str(vault_with_secrets),
        )
        assert exit_code == 42


class TestSecretIsolation:
    def test_secrets_not_in_parent_env(self, vault_with_secrets):
        """Secrets should NOT leak into the parent process environment."""
        import os
        run_with_secrets(
            "testpass",
            command=["echo", "test"],
            vault_path=str(vault_with_secrets),
        )
        assert "MY_API_KEY" not in os.environ
        assert "DB_URL" not in os.environ
