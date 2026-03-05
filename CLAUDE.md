# claude-approve

A Go CLI tool that acts as a Claude Code `PreToolUse` hook for auto-approving, denying, or escalating tool calls based on configurable TOML rules.

## Verification

```bash
go vet ./... && go test ./...
```

## Build

```bash
go build ./cmd/claude-approve/
```

## Architecture

- **Language**: Go 1.25+
- **Module**: `github.com/dokipen/claude-approve`

| Package | Purpose |
|---------|---------|
| `cmd/claude-approve/` | CLI entry point (`run`, `validate`, `test` subcommands) |
| `internal/engine/` | Rule evaluation, compound command splitting, decision aggregation |
| `internal/config/` | TOML parsing, regex compilation, validation |
| `internal/hook/` | JSON stdin/stdout types for the PreToolUse hook interface |
| `internal/shellsplit/` | Shell AST parser (via `mvdan.cc/sh/v3`) for splitting compound commands |
| `internal/audit/` | JSONL audit log writer |

### Dependencies

- `github.com/BurntSushi/toml` — Configuration parsing
- `mvdan.cc/sh/v3` — Shell command AST parser

### Hook Interface

- **Input**: JSON on stdin with `tool_name` and `tool_input` (untrusted)
- **Output**: JSON on stdout with `decision` (allow/deny/ask) and `reason`
- **No output** = passthrough to normal Claude Code permissions

### Rule Priority

Strictly enforced: **deny > ask > passthrough > allow**

Compound commands (&&, ||, ;, |) and `bash -c` / `sh -c` are split via the shell AST parser. Each sub-command is evaluated independently. Most restrictive decision wins.

## Security

claude-approve is security-critical — a bypass means an AI agent could execute dangerous commands undetected.

### Threat Model

| Threat | Description |
|--------|-------------|
| Regex bypass | Crafted commands evading deny rules (unicode, encoding, null bytes) |
| Shell splitting evasion | Compound commands hiding dangerous sub-commands from the parser |
| Config injection | Malformed TOML changing rule behavior |
| Path traversal | `..` or symlinks bypassing `file_path_regex` rules |
| Log injection | Crafted JSON corrupting the audit log |
| Denial of service | Pathological regexes or deeply nested shell commands |

### Security Review Checklist

- Shell splitting: does the parser handle all evasion techniques?
- Rule priority: is deny > ask > passthrough > allow strictly enforced?
- Regex anchoring: are `^` anchors used appropriately?
- Parse failure fallback: does it safely return the whole command as-is?
- Variable assignment stripping: does it preserve subshell extraction?

## Performance

- **Target**: < 50ms startup + evaluation (cold start)
- Every invocation is a fresh subprocess (no long-running server)
- Critical hotspot: `engine.Evaluate()` called per tool call

## Testing

```bash
# Coverage
go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out

# Single package
go test -v ./internal/engine/

# Single test
go test -v -run TestEvaluate/deny_blocks_bash ./internal/engine/

# Benchmarks
go test -bench=. -benchmem ./internal/engine/
go test -bench=. -benchmem ./internal/shellsplit/

# Manual testing
claude-approve test --config examples/hooks-config.toml --tool Bash --input '{"command":"rm -rf /"}'

# Config validation
claude-approve validate --config examples/hooks-config.toml
```

## Test Patterns

- Table-driven tests throughout (see `engine_test.go`, `shellsplit_test.go`)
- `config_integration_test.go` tests the example config against real audit log commands
- Use `t.Helper()` in test helpers
