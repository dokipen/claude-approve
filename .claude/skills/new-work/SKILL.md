---
name: new-work
description: Create a new worktree for feature development
version: 1.0.0
user-invocable: true
---

# Create a New Worktree

Usage: `/new-work <issue-number>-<branch-name>`

Branch names **MUST** be prefixed with the GitHub issue number (e.g., `42-add-regex-caching`).

## What This Does

1. Validates the branch name starts with an issue number
2. Creates a worktree at `.worktrees/<branch-name>`
3. Creates a new branch tracking `origin/main`

## Steps

```bash
# Validate branch name format
BRANCH_NAME="$1"
if ! echo "$BRANCH_NAME" | grep -qE '^[0-9]+-'; then
  echo "ERROR: Branch name must start with issue number (e.g., 42-add-feature)"
  exit 1
fi

# Fetch latest
git fetch origin

# Create worktree
git worktree add .worktrees/$BRANCH_NAME -b $BRANCH_NAME origin/main
```

## After Creation

```bash
cd .worktrees/$BRANCH_NAME
```

Then begin work in the worktree.

## Cleanup

```bash
git worktree remove .worktrees/<branch-name>
```

## Rules

- Always use worktrees — never work directly on main
- Branch names must start with the GitHub issue number
- One worktree per issue
