# agent-safe 🔐

> Secure credential proxy for AI coding agents — inject secrets safely, audit everything.

**The problem:** AI coding agents (Claude Code, Codex, Cursor, etc.) need API keys and secrets to work, but exposing them in environment variables, `.env` files, or config files means agents can read, copy, and accidentally leak them.

**The solution:** `agent-safe` wraps your agent commands with temporary, scoped credential injection. Secrets live in an encrypted vault, get injected only for the duration of the command, and are automatically cleaned up. Every access is logged.

## Quick Start

```bash
# Install
pip install .

# Initialize your vault (you'll set a master password)
agent-safe init

# Add secrets
agent-safe add API_KEY --desc "OpenAI API key"
agent-safe add DATABASE_URL --desc "Production database"

# Run an agent with secrets injected
agent-safe run -- claude-code "build a REST API"

# Only inject specific secrets
agent-safe run -s API_KEY -- python my_script.py
```

## How It Works

```
┌─────────────────────────────────────────────────┐
│                  agent-safe                       │
│                                                   │
│  1. Read secrets from encrypted vault             │
│  2. Inject into subprocess environment ONLY       │
│  3. Run your command                              │
│  4. Command exits → secrets vanish automatically  │
│  5. Log everything to audit trail                 │
│                                                   │
│  Secrets NEVER touch:                             │
│  ❌ Your shell environment                        │
│  ❌ Process listings (ps)                         │
│  ❌ Shell history                                 │
│  ❌ Disk (except encrypted vault)                 │
└─────────────────────────────────────────────────┘
```

## Installation

```bash
# From source
git clone https://github.com/jeevesbot-io/foundry-20260313-agent-safe.git
cd foundry-20260313-agent-safe
pip install .

# For development
pip install -e ".[dev]"
```

Requires Python 3.10+.

## Commands

### `agent-safe init`

Initialize a new encrypted vault. You'll be prompted to set a master password.

```bash
agent-safe init
# 🔑 Vault password: ****
# 🔑 Confirm password: ****
# ✅ Vault initialized at ~/.agent-safe
```

Use `--vault /path/to/vault` for a custom location.

### `agent-safe add <NAME>`

Add a secret to the vault.

```bash
# Interactive (prompted for value — most secure)
agent-safe add OPENAI_API_KEY --desc "Production OpenAI key"

# Or provide value directly (less secure — appears in history)
agent-safe add OPENAI_API_KEY --value "sk-..." --desc "Production OpenAI key"
```

### `agent-safe list`

List stored secrets (names and descriptions only — values are never shown).

```bash
agent-safe list
# ┌─────────────────────────────────────────────┐
# │ 🔐 Vault Secrets                            │
# ├──────────────┬───────────────┬───────────────┤
# │ Name         │ Description   │ Created       │
# ├──────────────┼───────────────┼───────────────┤
# │ OPENAI_KEY   │ OpenAI API    │ 2026-03-13    │
# │ DATABASE_URL │ Prod database │ 2026-03-13    │
# └──────────────┴───────────────┴───────────────┘
```

### `agent-safe remove <NAME>`

Remove a secret from the vault.

```bash
agent-safe remove OLD_API_KEY
```

### `agent-safe run -- <COMMAND>`

Run a command with secrets injected as environment variables. This is the core feature.

```bash
# Inject ALL secrets
agent-safe run -- claude-code "deploy the app"

# Inject specific secrets only
agent-safe run -s API_KEY -s DB_URL -- python deploy.py

# Works with any command
agent-safe run -- npm start
agent-safe run -- docker compose up
agent-safe run -s AWS_ACCESS_KEY_ID -s AWS_SECRET_ACCESS_KEY -- aws s3 ls
```

Secrets are injected into the subprocess environment only. When the command exits (success or failure), secrets are gone. They never touch your shell.

### `agent-safe import <FILE>`

Import secrets from a `.env` file.

```bash
agent-safe import .env
# ✅ Imported 5 secret(s): API_KEY, DB_URL, REDIS_URL, JWT_SECRET, SMTP_PASS
```

Existing secrets are preserved (not overwritten).

### `agent-safe audit`

View the audit log of all secret accesses.

```bash
agent-safe audit --last 10
# ┌──────────────────────────────────────────────────────────────────────┐
# │ 📋 Audit Log                                                        │
# ├─────────────────────┬──────────────┬──────────┬──────────────┬──────┤
# │ Timestamp           │ Action       │ Secrets  │ Command      │ Exit │
# ├─────────────────────┼──────────────┼──────────┼──────────────┼──────┤
# │ 2026-03-13T10:30:00 │ run          │ API_KEY  │ claude-code  │ —    │
# │ 2026-03-13T10:32:15 │ run_complete │ API_KEY  │ claude-code  │ 0    │
# └─────────────────────┴──────────────┴──────────┴──────────────┴──────┘
```

## Security Model

| Property | Detail |
|----------|--------|
| **Encryption** | Fernet (AES-128-CBC + HMAC-SHA256) |
| **Key derivation** | PBKDF2-HMAC-SHA256, 600k iterations |
| **Secret injection** | Subprocess env only — parent env untouched |
| **Cleanup** | Automatic on process exit |
| **Audit** | Append-only JSONL — every access logged |
| **At rest** | Vault file is encrypted; unreadable without password |

### What agent-safe does NOT do

- ❌ Integrate with cloud secret managers (1Password, AWS SM, Vault) — planned for v2
- ❌ Multi-user vault sharing
- ❌ Secret rotation or expiration
- ❌ Run a daemon or API server

## File Structure

```
~/.agent-safe/
├── vault.enc          # Encrypted vault (Fernet)
├── vault.meta.json    # Salt and metadata (not secret)
└── audit.jsonl        # Append-only access log
```

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest -v

# Run with coverage
pytest --cov=agent_safe --cov-report=term-missing
```

## Why?

AI coding agents are powerful but dangerous with credentials:

1. **Accidental leakage** — Agents echo env vars, write them to logs, or include them in generated code
2. **Scope creep** — An agent asked to "deploy the app" shouldn't need your AWS root credentials
3. **No visibility** — Without audit logging, you don't know what secrets an agent accessed
4. **Persistent exposure** — `.env` files and shell exports leave secrets accessible long after they're needed

`agent-safe` fixes this by making credential access temporary, scoped, and audited.

## License

MIT
