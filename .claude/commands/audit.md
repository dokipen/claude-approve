Analyze the claude-approve audit log and recommend config changes to reduce user prompts.

## Step 1: Locate the hooks config and audit log path

First, try to read `~/.claude/hooks-config.toml`:

```bash
cat "$HOME/.claude/hooks-config.toml" 2>/dev/null || echo "NOT_FOUND"
```

If that returns `NOT_FOUND`, check `~/.claude/settings.json` for a PreToolUse hook command that includes `--config`:

```bash
python3 -c "
import json, os, re
path = os.path.expanduser('~/.claude/settings.json')
try:
    with open(path) as f:
        data = json.load(f)
    hooks = data.get('hooks', {})
    pre = hooks.get('PreToolUse', [])
    for entry in (pre if isinstance(pre, list) else [pre]):
        cmd = ''
        if isinstance(entry, dict):
            matchers = entry.get('hooks', entry.get('matchers', []))
            for m in (matchers if isinstance(matchers, list) else [matchers]):
                if isinstance(m, dict):
                    for h in m.get('hooks', []):
                        cmd = cmd or (h.get('command', '') if isinstance(h, dict) else '')
        elif isinstance(entry, str):
            cmd = entry
        m = re.search(r'--config\s+(\S+)', cmd)
        if m:
            print('CONFIG_PATH:', m.group(1))
            break
    else:
        print('NOT_FOUND')
except Exception as e:
    print('ERROR:', e)
"
```

Determine the audit log path using this priority:
1. If `hooks-config.toml` was found, parse the `audit_file` value from the `[audit]` section.
2. If a `--config` path was found, read that TOML file and parse `audit_file` from it.
3. Otherwise, default to `~/.claude/claude-tool-audit.jsonl`.

Also note the `audit_level` value if found (default is `"matched"` if not set).

## Step 2: Show config path and confirm

Tell the user:
- The resolved audit log file path (with `~` expanded to the actual home directory)
- The `audit_level` if found (and explain what it means for passthrough entries)
- Ask: "Should I proceed with reading this file?"

Wait for confirmation before continuing.

## Step 3: Parse the JSONL and compute summary stats

Once confirmed, run the following analysis. Replace `AUDIT_LOG_PATH` with the resolved path:

```bash
python3 -c "
import json, os, sys
from collections import defaultdict

log_path = os.path.expanduser('AUDIT_LOG_PATH')

if not os.path.exists(log_path):
    print('MISSING')
    sys.exit(0)

entries = []
malformed = 0
with open(log_path) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            malformed += 1

if not entries:
    print('EMPTY')
    sys.exit(0)

total = len(entries)
counts = defaultdict(int)
for e in entries:
    counts[e.get('decision', 'unknown')] += 1

print(f'TOTAL:{total}')
print(f'MALFORMED:{malformed}')
for d in ['allow', 'deny', 'ask', 'passthrough']:
    print(f'DECISION_{d.upper()}:{counts[d]}')
"
```

Display:
- Total log entries
- Decision breakdown: allow / deny / ask / passthrough counts
- Number of malformed lines skipped
- If `EMPTY` or `MISSING`: show a friendly message (e.g. "No audit log entries found. Run some Claude Code sessions with claude-approve active first.") and stop.

## Step 4: Identify prompt-causing entries

Run the grouping analysis:

```bash
python3 -c "
import json, os, sys, shlex
from collections import defaultdict

log_path = os.path.expanduser('AUDIT_LOG_PATH')

entries = []
with open(log_path) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            pass

# Prompt-causing: ask or passthrough
prompt_entries = [e for e in entries if e.get('decision') in ('ask', 'passthrough')]
total_prompts = len(prompt_entries)

if total_prompts == 0:
    print('NO_PROMPTS')
    sys.exit(0)

groups = defaultdict(int)  # (pattern, tool) -> count

for e in prompt_entries:
    tool = e.get('tool_name', '')
    inp = e.get('tool_input', '')
    if tool == 'Bash':
        # First word of command
        try:
            parts = shlex.split(inp)
            prefix = parts[0] if parts else inp.split()[0] if inp.split() else '(empty)'
        except Exception:
            prefix = inp.split()[0] if inp.split() else '(empty)'
        groups[(prefix, 'Bash')] += 1
    elif tool in ('Read', 'Edit', 'Write'):
        # File extension
        _, ext = os.path.splitext(inp)
        pattern = ext if ext else '(no extension)'
        groups[(pattern, tool)] += 1
    elif tool in ('Grep', 'Glob'):
        groups[(tool, tool)] += 1
    else:
        groups[(inp[:40] if inp else '(empty)', tool)] += 1

sorted_groups = sorted(groups.items(), key=lambda x: -x[1])

print(f'TOTAL_PROMPTS:{total_prompts}')
for (pattern, tool), count in sorted_groups:
    pct = round(100 * count / total_prompts, 1)
    print(f'GROUP|{pattern}|{tool}|{count}|{pct}')
"
```

Display a table sorted by frequency (most frequent first):

```
Pattern          | Tool  | Count | % of Prompts
-----------------|-------|-------|-------------
git              | Bash  |    42 | 31.3%
npm              | Bash  |    18 | 13.4%
.ts              | Read  |    15 | 11.2%
...
```

## Step 5: Generate TOML recommendations

For each group from the table, generate a recommended `[[allow]]` rule. Skip groups that are already covered by an existing allow rule in the config (check `command_regex` or `file_path_regex` patterns).

Rules to generate:

- **Bash command prefix** (e.g. `git`):
  ```toml
  [[allow]]
  tool = "Bash"
  command_regex = "^git( |$)"
  reason = "Allow git commands (N prompts eliminated)"
  ```

- **File extension for Read** (e.g. `.ts`):
  ```toml
  [[allow]]
  tool = "Read"
  file_path_regex = "\\.ts$"
  reason = "Allow reading .ts files (N prompts eliminated)"
  ```

- **File extension for Edit/Write** (e.g. `.ts`):
  ```toml
  [[allow]]
  tool = "Edit"
  file_path_regex = "\\.ts$"
  reason = "Allow editing .ts files (N prompts eliminated)"
  ```

- **Grep or Glob** (tool appears in prompts):
  ```toml
  [[allow]]
  tool = "Grep"
  reason = "Allow all Grep calls (N prompts eliminated)"
  ```

Present the TOML blocks in order of highest impact first (most entries eliminated). Include a total impact estimate: "These rules would eliminate approximately X of Y prompts (Z%)."

If no recommendations are possible (all patterns already covered), say so.

## Step 6: Offer to apply changes

Ask the user: "Would you like me to append these recommended rules to your config file at `CONFIG_PATH`?"

- If **yes**: Append the TOML blocks to the config file (do not overwrite — use append). Add a comment header like `# Rules added by /audit on YYYY-MM-DD`. Confirm what was written.
- If **no**: Tell the user they can copy-paste the blocks above manually.
- If the config file path is unknown (no config found in step 1): Inform the user and suggest they add the rules to their config manually.
