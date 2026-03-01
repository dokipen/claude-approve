---
name: github-issues
description: GitHub issue management for claude-approve
version: 1.0.0
user-invocable: false
---

# GitHub Issue Management

Repository: `dokipen/claude-approve`

## Listing Issues

```bash
# Open issues
gh issue list -R dokipen/claude-approve

# Filter by label
gh issue list -R dokipen/claude-approve -l "feat"
gh issue list -R dokipen/claude-approve -l "estimate:5"

# Search
gh issue list -R dokipen/claude-approve -S "compound commands"

# JSON output
gh issue list -R dokipen/claude-approve --json number,title,labels,assignees
```

## Reading Issues

```bash
# View details
gh issue view <N> -R dokipen/claude-approve

# JSON fields
gh issue view <N> -R dokipen/claude-approve --json title,body,labels,assignees
```

## Creating Issues

```bash
gh issue create -R dokipen/claude-approve \
  --title "Clear description of the outcome" \
  --body "$(cat <<'EOF'
## Description
What and why.

## Acceptance Criteria
- [ ] Criterion 1
- [ ] Criterion 2

## Notes
Additional context.
EOF
)" \
  --label "feat" \
  --label "estimate:5"
```

## Title Conventions

- No prefixes (`feat:`, `fix:`, etc.) — use labels for type
- Describe the outcome, not the implementation

## Updating Issues

```bash
# Edit title/body
gh issue edit <N> -R dokipen/claude-approve --title "New title"
gh issue edit <N> -R dokipen/claude-approve --body "New body"

# Add/remove labels
gh issue edit <N> -R dokipen/claude-approve --add-label "blocked"
gh issue edit <N> -R dokipen/claude-approve --remove-label "blocked"

# Close/reopen
gh issue close <N> -R dokipen/claude-approve
gh issue reopen <N> -R dokipen/claude-approve
```

## Estimation

| Label | Meaning |
|-------|---------|
| `estimate:1` | Trivial, < 30 min |
| `estimate:2` | Small, straightforward |
| `estimate:3` | Medium-small, clear path |
| `estimate:5` | Medium, some complexity |
| `estimate:8` | Large, multiple components |
| `estimate:13` | Very large, consider splitting |

```bash
# Add estimate
gh issue edit <N> -R dokipen/claude-approve --add-label "estimate:5"
```

## Comments

```bash
# Add comment
gh issue comment <N> -R dokipen/claude-approve --body "Progress update"
```

## Agent Workflow

```bash
# Claim issue
gh issue edit <N> -R dokipen/claude-approve --add-assignee dokipen

# Mark complete
gh issue close <N> -R dokipen/claude-approve -c "Completed in #<PR>"
```
