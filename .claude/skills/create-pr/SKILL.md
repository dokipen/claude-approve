---
name: create-pr
description: Create a pull request for the current branch
version: 1.0.0
user-invocable: true
---

# Create Pull Request

## Pre-flight Checks

Run these before creating the PR:

```bash
# Must not be on main
BRANCH=$(git branch --show-current)
if [ "$BRANCH" = "main" ]; then
  echo "ERROR: Cannot create PR from main"
  exit 1
fi

# Static analysis
go vet ./...

# Tests
go test ./...

# Build
go build ./cmd/claude-approve/

# Check for uncommitted changes
git status

# Check for existing PR
gh pr list -R dokipen/claude-approve --head "$BRANCH"
```

## Commit and Push

If there are uncommitted changes:

```bash
git add <specific files>
git commit -m "<type>: <description>"
git push -u origin HEAD
```

Commit types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`

## Create PR

```bash
gh pr create -R dokipen/claude-approve \
  --title "<short description>" \
  --body "$(cat <<'EOF'
## Summary
- What changed and why

Fixes #<issue-number>

## Test Plan
- [ ] `go test ./...` passes
- [ ] `go vet ./...` clean
- [ ] Manual test: `echo '...' | ./claude-approve run --config examples/hooks-config.toml`
EOF
)"
```

## PR Title

- Keep under 70 characters
- Use imperative mood ("Add feature" not "Added feature")
- No type prefix needed — the PR title becomes the squash commit message

## After Creation

- Report the PR URL
- Note any CI checks that need to pass
- Mention if reviewers should be assigned
