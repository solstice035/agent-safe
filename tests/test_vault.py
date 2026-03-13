"""Tests for the vault module."""

import pytest
from pathlib import Path

from agent_safe.vault import (
    init_vault,
    add_secret,
    list_secrets,
    get_secrets,
    remove_secret,
    import_dotenv,
)


@pytest.fixture
def vault_dir(tmp_path):
    """Create a temporary vault for testing."""
    vault_path = tmp_path / "test-vault"
    init_vault("testpass123", vault_path=vault_path)
    return vault_path


class TestVaultInit:
    def test_init_creates_files(self, tmp_path):
        vault_path = tmp_path / "new-vault"
        result = init_vault("mypassword", vault_path=vault_path)
        assert result == vault_path
        assert (vault_path / "vault.enc").exists()
        assert (vault_path / "vault.meta.json").exists()

    def test_init_fails_if_exists(self, vault_dir):
        with pytest.raises(FileExistsError):
            init_vault("testpass123", vault_path=vault_dir)

    def test_empty_vault_has_no_secrets(self, vault_dir):
        secrets = list_secrets("testpass123", vault_path=vault_dir)
        assert secrets == []


class TestAddAndList:
    def test_add_single_secret(self, vault_dir):
        add_secret("testpass123", "API_KEY", "sk-12345", vault_path=vault_dir)
        secrets = list_secrets("testpass123", vault_path=vault_dir)
        assert len(secrets) == 1
        assert secrets[0]["name"] == "API_KEY"
        # Values should NOT be in list output
        assert "value" not in secrets[0]

    def test_add_multiple_secrets(self, vault_dir):
        add_secret("testpass123", "API_KEY", "sk-12345", vault_path=vault_dir)
        add_secret("testpass123", "DB_URL", "postgres://localhost", vault_path=vault_dir)
        add_secret("testpass123", "TOKEN", "abc-xyz", vault_path=vault_dir)
        secrets = list_secrets("testpass123", vault_path=vault_dir)
        assert len(secrets) == 3

    def test_add_duplicate_fails(self, vault_dir):
        add_secret("testpass123", "API_KEY", "sk-12345", vault_path=vault_dir)
        with pytest.raises(KeyError):
            add_secret("testpass123", "API_KEY", "sk-99999", vault_path=vault_dir)

    def test_add_with_description(self, vault_dir):
        add_secret(
            "testpass123", "API_KEY", "sk-12345",
            description="OpenAI key", vault_path=vault_dir,
        )
        secrets = list_secrets("testpass123", vault_path=vault_dir)
        assert secrets[0]["description"] == "OpenAI key"


class TestGetSecrets:
    def test_get_all_secrets(self, vault_dir):
        add_secret("testpass123", "KEY1", "val1", vault_path=vault_dir)
        add_secret("testpass123", "KEY2", "val2", vault_path=vault_dir)
        result = get_secrets("testpass123", vault_path=vault_dir)
        assert result == {"KEY1": "val1", "KEY2": "val2"}

    def test_get_specific_secrets(self, vault_dir):
        add_secret("testpass123", "KEY1", "val1", vault_path=vault_dir)
        add_secret("testpass123", "KEY2", "val2", vault_path=vault_dir)
        add_secret("testpass123", "KEY3", "val3", vault_path=vault_dir)
        result = get_secrets("testpass123", names=["KEY1", "KEY3"], vault_path=vault_dir)
        assert result == {"KEY1": "val1", "KEY3": "val3"}

    def test_get_missing_secret_fails(self, vault_dir):
        with pytest.raises(KeyError):
            get_secrets("testpass123", names=["NONEXISTENT"], vault_path=vault_dir)


class TestRemove:
    def test_remove_secret(self, vault_dir):
        add_secret("testpass123", "API_KEY", "sk-12345", vault_path=vault_dir)
        remove_secret("testpass123", "API_KEY", vault_path=vault_dir)
        secrets = list_secrets("testpass123", vault_path=vault_dir)
        assert len(secrets) == 0

    def test_remove_nonexistent_fails(self, vault_dir):
        with pytest.raises(KeyError):
            remove_secret("testpass123", "NOPE", vault_path=vault_dir)


class TestWrongPassword:
    def test_wrong_password_fails(self, vault_dir):
        add_secret("testpass123", "KEY", "val", vault_path=vault_dir)
        with pytest.raises(ValueError, match="Invalid password"):
            list_secrets("wrongpassword", vault_path=vault_dir)


class TestEncryption:
    def test_vault_file_is_not_plaintext(self, vault_dir):
        add_secret("testpass123", "MY_SECRET", "super-secret-value", vault_path=vault_dir)
        raw = (vault_dir / "vault.enc").read_bytes()
        assert b"super-secret-value" not in raw
        assert b"MY_SECRET" not in raw


class TestImportDotenv:
    def test_import_basic(self, vault_dir, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text(
            "API_KEY=sk-12345\n"
            "DB_URL=postgres://localhost\n"
            "# this is a comment\n"
            "\n"
            'QUOTED="hello world"\n'
        )
        imported = import_dotenv("testpass123", env_file, vault_path=vault_dir)
        assert sorted(imported) == ["API_KEY", "DB_URL", "QUOTED"]

        result = get_secrets("testpass123", vault_path=vault_dir)
        assert result["QUOTED"] == "hello world"

    def test_import_skips_existing(self, vault_dir, tmp_path):
        add_secret("testpass123", "API_KEY", "original", vault_path=vault_dir)

        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=new-value\nNEW_KEY=new\n")
        imported = import_dotenv("testpass123", env_file, vault_path=vault_dir)
        assert imported == ["NEW_KEY"]

        # Original value preserved
        result = get_secrets("testpass123", vault_path=vault_dir)
        assert result["API_KEY"] == "original"
