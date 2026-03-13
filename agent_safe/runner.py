"""Command runner with secure credential injection."""

from __future__ import annotations

import os
import subprocess
import sys
from typing import Optional

from .audit import log_access
from .vault import get_secrets


def run_with_secrets(
    password: str,
    command: list[str],
    secret_names: list[str] | None = None,
    vault_path: str | None = None,
) -> int:
    """Run a command with secrets injected as environment variables.

    Secrets are injected ONLY into the subprocess environment and are
    automatically cleaned up when the process exits. They never touch
    the parent process environment or shell history.

    Args:
        password: Vault master password.
        command: Command and arguments to run.
        secret_names: Specific secrets to inject. None = inject all.
        vault_path: Custom vault directory path.

    Returns:
        The exit code of the subprocess.
    """
    # Get secrets from vault
    secrets = get_secrets(password, names=secret_names, vault_path=vault_path)

    if not secrets:
        print("[agent-safe] Warning: No secrets to inject", file=sys.stderr)

    # Build subprocess environment: copy current env + inject secrets
    env = os.environ.copy()
    env.update(secrets)

    # Log the access
    cmd_str = " ".join(command)
    log_access(
        action="run",
        secret_names=list(secrets.keys()),
        command=cmd_str,
        vault_path=vault_path,
    )

    # Run the command with injected secrets
    try:
        result = subprocess.run(command, env=env)
        exit_code = result.returncode
    except FileNotFoundError:
        print(f"[agent-safe] Error: Command not found: {command[0]}", file=sys.stderr)
        exit_code = 127
    except KeyboardInterrupt:
        print("\n[agent-safe] Interrupted", file=sys.stderr)
        exit_code = 130

    # Log completion
    log_access(
        action="run_complete",
        secret_names=list(secrets.keys()),
        command=cmd_str,
        exit_code=exit_code,
        vault_path=vault_path,
    )

    # Secrets are NOT in our process env — only in the subprocess
    # which has already exited. Cleanup is automatic.

    return exit_code
