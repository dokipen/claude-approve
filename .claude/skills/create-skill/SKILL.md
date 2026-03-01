---
name: create-skill
description: Create a new Claude Code skill for this project
version: 1.0.0
user-invocable: true
---

# Create a New Skill

Usage: `/create-skill <name>`

## Skill Location

Skills live at `.claude/skills/<name>/SKILL.md`

## Frontmatter

```yaml
---
name: <kebab-case-name>
description: <one-line description>
version: 1.0.0
user-invocable: true          # user can invoke via /name
# disable-model-invocation: true  # only user can invoke, not the model
---
```

## Invocation Modes

| Setting | Meaning |
|---------|---------|
| `user-invocable: false` | Background knowledge only — never shown as a slash command |
| `disable-model-invocation: true` | User-only — model cannot trigger it (use for side effects) |
| Both omitted | Both user and model can invoke |

## Existing Skills

| Skill | Purpose |
|-------|---------|
| `new-work` | Create worktrees for feature branches |
| `create-skill` | Create new skills (this one) |
| `lead` | Technical lead workflow |
| `github-issues` | GitHub issue management |
| `refine` | Ticket refinement |
| `create-pr` | Create pull requests |

## Writing Guidelines

- Use imperative language ("Run tests", not "You should run tests")
- Keep under ~100 lines
- Include concrete commands and values, not vague instructions
- Reference project-specific paths, tools, and conventions

## After Creating

Commit and push to make the skill available:

```bash
git add .claude/skills/<name>/SKILL.md
git commit -m "feat: Add <name> skill"
git push
```
