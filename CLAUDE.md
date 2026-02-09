**溝通規範** : 用戶對話採用繁體中文

# Atlas-Local Development Guidelines

Auto-generated from all feature plans. Last updated: 2026-02-07

## Active Technologies

- Rust 2024 edition, stable toolchain only (no nightly features) + ree-sitter (AST parsing), clap v4 (CLI), rayon (parallelism), rhai (scripting rules), tracing (structured logging), indicatif (progress), tower-lsp (LSP server), ed25519-dalek (rulepack signing), rusqlite (cache), bincode (cache serialization), serde/serde_json (serialization), thiserror (library errors), anyhow (CLI errors), criterion (benchmarks) (001-atlas-local-sast)

## Project Structure

```text
src/
tests/
```

## Commands

cargo test [ONLY COMMANDS FOR ACTIVE TECHNOLOGIES][ONLY COMMANDS FOR ACTIVE TECHNOLOGIES] cargo clippy

## Code Style

Rust 2024 edition, stable toolchain only (no nightly features): Follow standard conventions

## Recent Changes

- 001-atlas-local-sast: Added Rust 2024 edition, stable toolchain only (no nightly features) + ree-sitter (AST parsing), clap v4 (CLI), rayon (parallelism), rhai (scripting rules), tracing (structured logging), indicatif (progress), tower-lsp (LSP server), ed25519-dalek (rulepack signing), rusqlite (cache), bincode (cache serialization), serde/serde_json (serialization), thiserror (library errors), anyhow (CLI errors), criterion (benchmarks)

## Code Conventions

### Language

- **程式碼註解**: 繁體中文
- **技術術語**: 保留英文
- **Commit Message**: Conventional Commits (feat/fix/docs/refactor/test/chore)
