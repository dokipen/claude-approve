---
name: refine
description: Refine GitHub issues for development readiness
version: 1.0.0
user-invocable: true
---

# Refine Issues

Usage:
- `/refine` — refine all unrefined open issues
- `/refine 123` — refine a specific issue

## Single Issue

Delegate to the `ticket-refiner` agent:

```
Review and refine issue #<N> in dokipen/claude-approve.
Check all refinement criteria and report status.
```

## Batch Refinement

1. Find unrefined issues:
   ```bash
   gh issue list -R dokipen/claude-approve --json number,title,labels \
     | jq '[.[] | select(.labels | map(.name) | contains(["refined"]) | not)]'
   ```

2. For each unrefined issue, delegate to the `ticket-refiner` agent

3. Report summary of all issues and their status

## Refinement Criteria

1. Clear title (no type prefixes)
2. Acceptance criteria present
3. Estimate label assigned
4. Type label assigned
5. Assigned to dokipen
6. In GitHub Project
7. Blockers linked
8. Blocked label correct
9. Refined label added

## Notes

- The `ticket-refiner` agent handles the detailed review
- Ask the user before making subjective decisions (estimates, title rewording)
- Always add the `refined` label last, after all other criteria are met
