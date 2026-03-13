"""Encrypted vault operations using Fernet with PBKDF2-derived keys."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .models import SecretEntry, VaultData, VaultMetadata

DEFAULT_VAULT_DIR = Path.home() / ".agent-safe"
VAULT_FILE = "vault.enc"
META_FILE = "vault.meta.json"
PBKDF2_ITERATIONS = 600_000


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def get_vault_dir(vault_path: str | Path | None = None) -> Path:
    """Get the vault directory, creating it if needed."""
    path = Path(vault_path) if vault_path else DEFAULT_VAULT_DIR
    return path


def init_vault(password: str, vault_path: str | Path | None = None) -> Path:
    """Initialize a new encrypted vault.

    Returns the vault directory path.
    """
    vault_dir = get_vault_dir(vault_path)
    vault_dir.mkdir(parents=True, exist_ok=True)

    vault_file = vault_dir / VAULT_FILE
    meta_file = vault_dir / META_FILE

    if vault_file.exists():
        raise FileExistsError(f"Vault already exists at {vault_dir}")

    # Generate salt
    salt = os.urandom(32)

    # Create metadata
    meta = VaultMetadata(salt=salt.hex())
    meta_file.write_text(meta.model_dump_json(indent=2))

    # Create empty vault
    key = _derive_key(password, salt)
    fernet = Fernet(key)

    empty_vault = VaultData()
    encrypted = fernet.encrypt(empty_vault.model_dump_json().encode())
    vault_file.write_bytes(encrypted)

    return vault_dir


def _load_meta(vault_dir: Path) -> VaultMetadata:
    """Load vault metadata."""
    meta_file = vault_dir / META_FILE
    if not meta_file.exists():
        raise FileNotFoundError(f"No vault found at {vault_dir}")
    return VaultMetadata.model_validate_json(meta_file.read_text())


def _decrypt_vault(password: str, vault_dir: Path) -> tuple[VaultData, Fernet]:
    """Decrypt and return vault data and the Fernet instance."""
    meta = _load_meta(vault_dir)
    salt = bytes.fromhex(meta.salt)
    key = _derive_key(password, salt)
    fernet = Fernet(key)

    vault_file = vault_dir / VAULT_FILE
    if not vault_file.exists():
        raise FileNotFoundError(f"No vault file at {vault_file}")

    try:
        decrypted = fernet.decrypt(vault_file.read_bytes())
    except InvalidToken:
        raise ValueError("Invalid password — cannot decrypt vault")

    vault_data = VaultData.model_validate_json(decrypted)
    return vault_data, fernet


def _save_vault(vault_data: VaultData, fernet: Fernet, vault_dir: Path) -> None:
    """Encrypt and save vault data."""
    vault_file = vault_dir / VAULT_FILE
    encrypted = fernet.encrypt(vault_data.model_dump_json().encode())
    vault_file.write_bytes(encrypted)


def add_secret(
    password: str,
    name: str,
    value: str,
    description: str | None = None,
    vault_path: str | Path | None = None,
) -> None:
    """Add a secret to the vault."""
    vault_dir = get_vault_dir(vault_path)
    vault_data, fernet = _decrypt_vault(password, vault_dir)

    if name in vault_data.secrets:
        raise KeyError(f"Secret '{name}' already exists. Remove it first to update.")

    vault_data.secrets[name] = SecretEntry(
        name=name, value=value, description=description
    )
    _save_vault(vault_data, fernet, vault_dir)


def remove_secret(
    password: str, name: str, vault_path: str | Path | None = None
) -> None:
    """Remove a secret from the vault."""
    vault_dir = get_vault_dir(vault_path)
    vault_data, fernet = _decrypt_vault(password, vault_dir)

    if name not in vault_data.secrets:
        raise KeyError(f"Secret '{name}' not found in vault")

    del vault_data.secrets[name]
    _save_vault(vault_data, fernet, vault_dir)


def list_secrets(
    password: str, vault_path: str | Path | None = None
) -> list[dict]:
    """List all secrets (names and descriptions only, not values)."""
    vault_dir = get_vault_dir(vault_path)
    vault_data, _ = _decrypt_vault(password, vault_dir)

    return [
        {
            "name": s.name,
            "description": s.description,
            "created_at": s.created_at,
        }
        for s in vault_data.secrets.values()
    ]


def get_secrets(
    password: str,
    names: list[str] | None = None,
    vault_path: str | Path | None = None,
) -> dict[str, str]:
    """Get secret values as a dict of name -> value.

    If names is None, returns all secrets.
    """
    vault_dir = get_vault_dir(vault_path)
    vault_data, _ = _decrypt_vault(password, vault_dir)

    if names is None:
        return {s.name: s.value for s in vault_data.secrets.values()}

    result = {}
    for name in names:
        if name not in vault_data.secrets:
            raise KeyError(f"Secret '{name}' not found in vault")
        result[name] = vault_data.secrets[name].value

    return result


def import_dotenv(
    password: str, env_file: str | Path, vault_path: str | Path | None = None
) -> list[str]:
    """Import secrets from a .env file into the vault.

    Returns list of imported secret names.
    """
    vault_dir = get_vault_dir(vault_path)
    vault_data, fernet = _decrypt_vault(password, vault_dir)

    env_path = Path(env_file)
    if not env_path.exists():
        raise FileNotFoundError(f"File not found: {env_path}")

    imported = []
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue

        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()

        # Remove surrounding quotes
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]

        if key and key not in vault_data.secrets:
            vault_data.secrets[key] = SecretEntry(
                name=key, value=value, description=f"Imported from {env_path.name}"
            )
            imported.append(key)

    _save_vault(vault_data, fernet, vault_dir)
    return imported
