"""agent-safe CLI — secure credential proxy for AI coding agents."""

from __future__ import annotations

import getpass
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .audit import log_access, read_audit_log
from .runner import run_with_secrets
from .vault import (
    add_secret,
    get_vault_dir,
    import_dotenv,
    init_vault,
    list_secrets,
    remove_secret,
)

app = typer.Typer(
    name="agent-safe",
    help="🔐 Secure credential proxy for AI coding agents",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()

VaultOption = Annotated[
    Optional[str],
    typer.Option("--vault", "-v", help="Custom vault directory path"),
]


def _get_password(confirm: bool = False) -> str:
    """Prompt for the vault master password."""
    password = getpass.getpass("🔑 Vault password: ")
    if not password:
        console.print("[red]Error: Password cannot be empty[/red]")
        raise typer.Exit(1)
    if confirm:
        password2 = getpass.getpass("🔑 Confirm password: ")
        if password != password2:
            console.print("[red]Error: Passwords do not match[/red]")
            raise typer.Exit(1)
    return password


@app.command()
def version():
    """Show the agent-safe version."""
    console.print(f"agent-safe v{__version__}")


@app.command()
def init(vault: VaultOption = None):
    """Initialize a new encrypted vault."""
    vault_dir = get_vault_dir(vault)
    if (vault_dir / "vault.enc").exists():
        console.print(f"[red]Vault already exists at {vault_dir}[/red]")
        raise typer.Exit(1)

    console.print("[bold]Initializing new agent-safe vault...[/bold]")
    password = _get_password(confirm=True)

    try:
        path = init_vault(password, vault_path=vault)
        log_access(action="init", vault_path=vault)
        console.print(f"[green]✅ Vault initialized at {path}[/green]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def add(
    name: Annotated[str, typer.Argument(help="Secret name (used as env var name)")],
    value: Annotated[
        Optional[str],
        typer.Option("--value", help="Secret value (prompted if not provided)"),
    ] = None,
    description: Annotated[
        Optional[str], typer.Option("--desc", "-d", help="Optional description")
    ] = None,
    vault: VaultOption = None,
):
    """Add a secret to the vault."""
    password = _get_password()

    if value is None:
        value = getpass.getpass(f"🔒 Value for {name}: ")
        if not value:
            console.print("[red]Error: Secret value cannot be empty[/red]")
            raise typer.Exit(1)

    try:
        add_secret(password, name, value, description=description, vault_path=vault)
        log_access(action="add", secret_names=[name], vault_path=vault)
        console.print(f"[green]✅ Secret '{name}' added to vault[/green]")
    except KeyError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="list")
def list_cmd(vault: VaultOption = None):
    """List all secrets in the vault (names only, no values)."""
    password = _get_password()

    try:
        secrets = list_secrets(password, vault_path=vault)
        log_access(action="list", vault_path=vault)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)

    if not secrets:
        console.print("[dim]Vault is empty — add secrets with `agent-safe add`[/dim]")
        return

    table = Table(title="🔐 Vault Secrets")
    table.add_column("Name", style="cyan bold")
    table.add_column("Description", style="dim")
    table.add_column("Created", style="dim")

    for s in secrets:
        table.add_row(s["name"], s.get("description", "—"), s["created_at"][:10])

    console.print(table)
    console.print(f"\n[dim]{len(secrets)} secret(s) stored[/dim]")


@app.command()
def remove(
    name: Annotated[str, typer.Argument(help="Secret name to remove")],
    vault: VaultOption = None,
):
    """Remove a secret from the vault."""
    password = _get_password()

    try:
        remove_secret(password, name, vault_path=vault)
        log_access(action="remove", secret_names=[name], vault_path=vault)
        console.print(f"[green]✅ Secret '{name}' removed[/green]")
    except (KeyError, FileNotFoundError, ValueError) as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def run(
    command: Annotated[
        list[str],
        typer.Argument(help="Command to run with injected secrets"),
    ],
    secrets: Annotated[
        Optional[list[str]],
        typer.Option("--secret", "-s", help="Specific secrets to inject (default: all)"),
    ] = None,
    vault: VaultOption = None,
):
    """Run a command with secrets securely injected as environment variables.

    Secrets are injected ONLY into the subprocess — they never touch your
    shell environment, process listing, or command history.

    Example:
        agent-safe run -- python my_script.py
        agent-safe run -s API_KEY -s DB_URL -- claude-code task.md
    """
    password = _get_password()

    try:
        exit_code = run_with_secrets(
            password,
            command=command,
            secret_names=secrets,
            vault_path=vault,
        )
    except (FileNotFoundError, ValueError, KeyError) as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)

    raise typer.Exit(exit_code)


@app.command(name="import")
def import_cmd(
    env_file: Annotated[
        str, typer.Argument(help="Path to .env file to import")
    ],
    vault: VaultOption = None,
):
    """Import secrets from a .env file into the vault."""
    password = _get_password()

    try:
        imported = import_dotenv(password, env_file, vault_path=vault)
        log_access(action="import", secret_names=imported, vault_path=vault)

        if imported:
            console.print(
                f"[green]✅ Imported {len(imported)} secret(s): {', '.join(imported)}[/green]"
            )
        else:
            console.print("[yellow]No new secrets found to import[/yellow]")
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def audit(
    last: Annotated[
        int, typer.Option("--last", "-n", help="Show last N entries")
    ] = 20,
    vault: VaultOption = None,
):
    """View the audit log of secret accesses."""
    entries = read_audit_log(vault_path=vault, last_n=last)

    if not entries:
        console.print("[dim]No audit log entries found[/dim]")
        return

    table = Table(title="📋 Audit Log")
    table.add_column("Timestamp", style="dim", width=20)
    table.add_column("Action", style="cyan")
    table.add_column("Secrets", style="yellow")
    table.add_column("Command", style="dim", max_width=40)
    table.add_column("Exit", style="dim", width=5)

    for entry in entries:
        table.add_row(
            entry.timestamp[:19],
            entry.action,
            ", ".join(entry.secret_names) if entry.secret_names else "—",
            entry.command or "—",
            str(entry.exit_code) if entry.exit_code is not None else "—",
        )

    console.print(table)


if __name__ == "__main__":
    app()
