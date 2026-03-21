# claude-approve

A Claude Code `PreToolUse` hook that auto-approves, denies, or escalates tool calls based on configurable TOML rules.

Instead of clicking "allow" on every safe command or worrying about dangerous ones slipping through, define rules once and let `claude-approve` handle permission decisions automatically.

## Install

```bash
go install github.com/dokipen/claude-approve/cmd/claude-approve@latest
```

Or build from source:

```bash
git clone https://github.com/dokipen/claude-approve.git
cd claude-approve
go build -o claude-approve ./cmd/claude-approve/
# Move to somewhere on your PATH
mv claude-approve /usr/local/bin/
```

## Quick Start

1. Create a config file at `~/.claude/hooks-config.toml`:

```toml
[[deny]]
tool = "Bash"
command_regex = "^rm .*-rf"
reason = "Dangerous recursive delete"

[[allow]]
tool = "Bash"
command_regex = "^(git|flutter|dart|go) "
command_exclude_regex = "&&|;|\\||`"
reason = "Standard dev commands without shell chaining"

[[allow]]
tool = "Read"
file_path_regex = ".*"
reason = "Allow all reads"
```

2. Add the hook to your Claude Code settings (`.claude/settings.json` or `.claude/settings.local.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "claude-approve run --config ~/.claude/hooks-config.toml"
          }
        ]
      }
    ]
  }
}
```

> **Note**: Use `"matcher": ".*"` to send all tool calls through claude-approve.
> Tools without matching rules will passthrough to Claude Code's normal permission system.

3. Use Claude Code as normal. Matching tool calls will be auto-approved or denied based on your rules.

## Rule Types

Rules are evaluated in priority order: **deny > ask > allow > log**.

| Type | Effect |
|------|--------|
| `deny` | Block the tool call. Claude sees the reason and adjusts. |
| `ask` | Prompt the user via Claude Code's built-in permission dialog. |
| `allow` | Auto-approve the tool call silently. |
| `log` | Write an audit entry but don't affect the permission decision. |

If no rule matches, the tool call falls through to Claude Code's normal permission system (passthrough).

## Tool Matching

### Built-in tools

These tools have structured input matching via `command_regex` / `file_path_regex`:

| Tool | Match fields |
|------|-------------|
| `Bash` | `command_regex`, `command_exclude_regex` |
| `Read` | `file_path_regex`, `file_path_exclude_regex` |
| `Edit` | `file_path_regex`, `file_path_exclude_regex` |
| `Write` | `file_path_regex`, `file_path_exclude_regex` |
| `Grep` | `file_path_regex`, `file_path_exclude_regex` |
| `Glob` | `file_path_regex`, `file_path_exclude_regex` |

Each rule matches on:
- **Include regex**: the tool call must match this pattern
- **Exclude regex** (optional): if the tool call also matches this, the rule is skipped

This "allow X but not if it also matches Y" pattern prevents command injection while permitting legitimate operations.

### Generic tools (MCP, WebFetch, WebSearch, etc.)

Use `tool_regex` to match any tool by name pattern. This is useful for MCP servers, web tools, and other tools that don't have structured input fields:

```toml
# Allow all tools from a specific MCP server
[[allow]]
tool_regex = "^mcp__workshop__"
reason = "Workshop MCP tools"

# Allow web tools
[[allow]]
tool_regex = "^Web(Fetch|Search)$"
reason = "Web tools"

# Deny a specific MCP tool
[[deny]]
tool_regex = "^mcp__dangerous__delete"
reason = "Dangerous MCP operation"
```

Rules with `tool_regex` match on the tool name only (no input constraints). If you add `command_regex` or `file_path_regex` to a `tool_regex` rule, it will only match tools that have those input fields (Bash, Read, etc.).

Each rule must have exactly one of `tool` (exact match) or `tool_regex` (regex match).

## Configuration

Full example at [examples/hooks-config.toml](examples/hooks-config.toml).

```toml
[audit]
audit_file = "/tmp/claude-tool-audit.jsonl"
audit_level = "matched"  # off | matched | all

# Deny dangerous commands
[[deny]]
tool = "Bash"
command_regex = "^rm .*-rf"
reason = "Dangerous recursive delete"

# Auto-approve safe commands (no shell chaining)
[[allow]]
tool = "Bash"
command_regex = "^(git|flutter|dart|go) "
command_exclude_regex = "&&|;|\\||`|\\$\\("
reason = "Dev commands without chaining"

# Auto-approve MCP tools from trusted servers
[[allow]]
tool_regex = "^mcp__workshop__"
reason = "Workshop MCP tools"

# Auto-approve web tools
[[allow]]
tool_regex = "^Web(Fetch|Search)$"
reason = "Web tools"

# Prompt for confirmation on lock files
[[ask]]
tool = "Edit"
file_path_regex = "\\.lock$"
reason = "Lock files need confirmation"

# Audit all bash commands
[[log]]
tool = "Bash"
command_regex = ".*"
reason = "Audit all bash"
```

### Audit Logging

Set `audit_level` to control what gets logged:

- `off` — no logging
- `matched` (default) — log only when a rule matches
- `all` — log every tool call, even passthrough

Each line in the audit file is a JSON object:

```json
{"timestamp":"2026-03-01T14:22:29Z","tool_name":"Bash","tool_input":"git status","rule_type":"allow","rule_tool":"Bash","rule_reason":"Dev commands","decision":"allow"}
```

## CLI Commands

### `run` — Hook mode

Reads Claude Code's JSON payload from stdin, evaluates rules, writes the permission decision to stdout.

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"git status"}}' | claude-approve run --config ~/.claude/hooks-config.toml
```

### `validate` — Check config

Validates the TOML config and reports rule counts.

```bash
claude-approve validate --config ~/.claude/hooks-config.toml
# config OK: 3 deny, 5 allow, 2 ask, 1 log rules
# audit: level=matched, file=/tmp/claude-tool-audit.jsonl
```

### `test` — Test a rule

Test how a specific tool call would be evaluated without running as a hook.

```bash
claude-approve test --config ~/.claude/hooks-config.toml --tool Bash --input '{"command":"rm -rf /"}'
# tool:     Bash
# decision: deny
# reason:   Dangerous recursive delete
# matched:  deny rule (tool=Bash, command_regex=^rm .*-rf)
```

## How It Works

1. Claude Code invokes `claude-approve run` before each tool call via the `PreToolUse` hook
2. The hook reads the JSON payload from stdin containing the tool name and parameters
3. Rules are evaluated in priority order (deny > ask > allow), with log rules collected separately
4. The decision is returned as JSON to stdout:
   - `allow` — auto-approves the tool call
   - `deny` — blocks with a reason shown to Claude
   - `ask` — falls back to Claude Code's interactive prompt
   - No output — passthrough to normal permissions

## Credits

Inspired by [kornysietsma/claude-code-permissions-hook](https://github.com/kornysietsma/claude-code-permissions-hook) and the [blog post](https://blog.korny.info/2025/10/10/better-claude-code-permissions) describing the approach.
