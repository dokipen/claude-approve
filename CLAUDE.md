# claude-approve

A Go CLI tool that acts as a Claude Code `PreToolUse` hook for auto-approving, denying, or escalating tool calls based on configurable TOML rules.

## Verification

```bash
go vet ./... && go test ./...
```

Run vulnerability check (requires `govulncheck` — install with `go install golang.org/x/vuln/cmd/govulncheck@latest`):

```bash
make vuln
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

**Regex Anchoring**: `file_path_regex` uses Go's `regexp.MatchString` — unanchored substring matching. The path is NOT canonicalized before matching. This has two important consequences:

- A deny rule `\\.env` matches `/project/.env.local` (substring match on `.env`)
- An allow rule `safe_dir` matches `/safe_dir/../../etc/shadow` (traversal bypass)

For Read/Edit/Write, matching is against `tool_input.file_path`. For Grep/Glob/Search, matching is against `tool_input.path`. Always use `^` to anchor patterns to the path start and `$` to anchor extension patterns to the path end (e.g., `\\.env$` instead of `\\.env`).

### Security Review Focus Areas

- **`internal/shellsplit/`**: Does the parser handle heredocs, process substitution, brace expansion? Can backtick/subshell nesting hide commands? Parse failure fallback must return the whole command as-is.
- **`internal/engine/`**: Is deny > ask > passthrough > allow strictly enforced? Can crafted input match include but dodge exclude? Regex matches are NOT anchored (uses `MatchString`). All `file_path_regex` patterns are substring matches — users must use `^` and `$` anchors explicitly. Can compound aggregation produce unsafe outcomes?
- **`internal/hook/`**: JSON parsing of unexpected/missing/oversized fields. Tool input is untrusted.
- **Dependencies**: Run `govulncheck ./...` to check for known vulnerabilities.

## Performance

- **Target**: < 50ms startup + evaluation (cold start)
- Every invocation is a fresh subprocess (no long-running server): start → read stdin JSON → parse TOML config → compile regexes → evaluate rules → write stdout JSON → exit
- Critical hotspot: `engine.Evaluate()` called per tool call
- Watch for unnecessary allocations in hot paths
- Shell parser (`mvdan.cc/sh/v3/syntax`) only invoked for Bash commands with compound operators — simple commands should short-circuit

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
- `wantLogCount: -1` means "skip log count check" in engine tests

## Code Review Criteria

### Critical (must fix)
- Security: regex injection, command injection via shellsplit bypass, path traversal
- Correctness: wrong decision priority, broken rule evaluation order
- Data races: concurrent access without synchronization
- Panics: nil pointer dereference, index out of bounds

### Warnings
- Missing test coverage for new logic paths
- Unhelpful error messages
- Regex patterns that compile but don't match developer intent
- Unnecessary allocations in hot paths

### Style
- Prefer `errors.New` over `fmt.Errorf` when no formatting needed, use `%w` for wrapping
- Table-driven tests for new test cases
- Keep functions short and focused

## Ticket Provider
provider: issues-api
api_url: https://cadence.bootsy.internal
project_id: claude-approve
