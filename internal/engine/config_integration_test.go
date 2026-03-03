package engine

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/dokipen/claude-approve/internal/config"
	"github.com/dokipen/claude-approve/internal/hook"
)

// exampleConfigPath returns the absolute path to examples/hooks-config.toml.
func exampleConfigPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "examples", "hooks-config.toml")
}

func loadExampleConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load(exampleConfigPath(t))
	if err != nil {
		t.Fatalf("failed to load example config: %v", err)
	}
	return cfg
}

// TestExampleConfig tests the example hooks-config.toml against real commands
// observed in production audit logs. This catches regressions when the config
// or engine changes.
func TestExampleConfig(t *testing.T) {
	cfg := loadExampleConfig(t)

	tests := []struct {
		name         string
		toolName     string
		command      string
		filePath     string
		wantDecision Decision
	}{
		// ── Bash: deny ──────────────────────────────

		{
			name:         "deny: rm -rf",
			toolName:     "Bash",
			command:      "rm -rf /",
			wantDecision: DecisionDeny,
		},
		{
			name:         "deny: rm with path -rf",
			toolName:     "Bash",
			command:      "rm -rf /Users/bob/src/project/.mockups/",
			wantDecision: DecisionDeny,
		},
		{
			name:         "deny: chmod",
			toolName:     "Bash",
			command:      "chmod +x scripts/deploy.sh",
			wantDecision: DecisionDeny,
		},
		{
			name:         "deny: chown",
			toolName:     "Bash",
			command:      "chown root:root /etc/config",
			wantDecision: DecisionDeny,
		},
		{
			name:         "deny: sudo",
			toolName:     "Bash",
			command:      "sudo apt install curl",
			wantDecision: DecisionDeny,
		},

		// ── Bash: allow — dev tools ─────────────────

		{
			name:         "allow: git status",
			toolName:     "Bash",
			command:      "git status",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: git -C flag",
			toolName:     "Bash",
			command:      "git -C /Users/bob/src/project status",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: go test with redirect",
			toolName:     "Bash",
			command:      "go test ./... 2>&1",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: go vet",
			toolName:     "Bash",
			command:      "go vet ./...",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: gh pr view",
			toolName:     "Bash",
			command:      `gh pr view 123 --repo owner/repo --json state --jq '.state'`,
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: gh issue list",
			toolName:     "Bash",
			command:      "gh issue list -R owner/repo --state open",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: flutter analyze",
			toolName:     "Bash",
			command:      "flutter analyze",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: dart format",
			toolName:     "Bash",
			command:      "dart format .",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: python3 script",
			toolName:     "Bash",
			command:      "python3 -m pytest tests/",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: sbt compile",
			toolName:     "Bash",
			command:      "sbt compile",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: ruby script",
			toolName:     "Bash",
			command:      "ruby -e 'puts 1'",
			wantDecision: DecisionAllow,
		},

		// ── Bash: allow — simple commands ───────────

		{
			name:         "allow: ls with args",
			toolName:     "Bash",
			command:      "ls -la /Users/bob/src/project",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: pwd no args",
			toolName:     "Bash",
			command:      "pwd",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: ls no args",
			toolName:     "Bash",
			command:      "ls",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: env no args",
			toolName:     "Bash",
			command:      "env",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: bash script",
			toolName:     "Bash",
			command:      "bash /tmp/script.sh",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: bash -c",
			toolName:     "Bash",
			command:      "bash -c 'echo hello'",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: cat file",
			toolName:     "Bash",
			command:      "cat /etc/hosts",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: echo",
			toolName:     "Bash",
			command:      "echo $PATH",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: grep with alternation pattern",
			toolName:     "Bash",
			command:      `grep -n "foo\|bar" file.txt`,
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: grep -rn",
			toolName:     "Bash",
			command:      `grep -rn "TODO" src/`,
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: head",
			toolName:     "Bash",
			command:      "head -20 file.txt",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: tail",
			toolName:     "Bash",
			command:      "tail -f /tmp/log.txt",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: curl",
			toolName:     "Bash",
			command:      "curl -sL https://example.com",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: npm install",
			toolName:     "Bash",
			command:      "npm install",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: make",
			toolName:     "Bash",
			command:      "make test",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: mkdir",
			toolName:     "Bash",
			command:      "mkdir -p /tmp/test",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: find",
			toolName:     "Bash",
			command:      "find . -name '*.go'",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: wc",
			toolName:     "Bash",
			command:      "wc -l file.txt",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: which",
			toolName:     "Bash",
			command:      "which go",
			wantDecision: DecisionAllow,
		},

		// ── Bash: allow — shell builtins ────────────

		{
			name:         "allow: cd",
			toolName:     "Bash",
			command:      "cd /Users/bob/src/project",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: true",
			toolName:     "Bash",
			command:      "true",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: false",
			toolName:     "Bash",
			command:      "false",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: pushd",
			toolName:     "Bash",
			command:      "pushd /tmp",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: source",
			toolName:     "Bash",
			command:      "source .env.local",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: set -e",
			toolName:     "Bash",
			command:      "set -e",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: read",
			toolName:     "Bash",
			command:      "read line",
			wantDecision: DecisionAllow,
		},

		// ── Bash: allow — project scripts ───────────

		{
			name:         "allow: project script",
			toolName:     "Bash",
			command:      "./scripts/deploy.sh",
			wantDecision: DecisionAllow,
		},

		// ── Bash: allow — compound commands ─────────

		{
			name:         "allow: cd && git status",
			toolName:     "Bash",
			command:      "cd /Users/bob/src/project && git status",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: git status && git log",
			toolName:     "Bash",
			command:      "git status && git log --oneline -5",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: cat | grep pipe",
			toolName:     "Bash",
			command:      "cat file.txt | grep error",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: gh with heredoc",
			toolName:     "Bash",
			command:      "gh pr create --title \"fix\" --body \"$(cat <<'EOF'\n## Summary\nfoo | bar\nEOF\n)\"",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: export && gh command",
			toolName:     "Bash",
			command:      "export PATH=/opt/homebrew/bin:$PATH && gh pr view 123",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: git worktree && cd",
			toolName:     "Bash",
			command:      "git worktree add .worktrees/feature -b feature && cd .worktrees/feature",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: VAR=$(cmd) && use (assignment skipped)",
			toolName:     "Bash",
			command:      "OWNER=$(gh api user --jq '.login') && echo $OWNER",
			wantDecision: DecisionAllow,
		},

		// ── Bash: deny in compound ──────────────────

		{
			name:         "deny: compound with rm -rf",
			toolName:     "Bash",
			command:      "git status && rm -rf /",
			wantDecision: DecisionDeny,
		},
		{
			name:         "deny: cd && chmod",
			toolName:     "Bash",
			command:      "cd /project && chmod +x script.sh",
			wantDecision: DecisionDeny,
		},
		{
			name:         "deny: rm -rf in assignment",
			toolName:     "Bash",
			command:      "RESULT=$(rm -rf /) && echo done",
			wantDecision: DecisionDeny,
		},

		// ── Bash: passthrough ───────────────────────

		{
			name:         "passthrough: unknown command",
			toolName:     "Bash",
			command:      "unknown_tool --flag",
			wantDecision: DecisionPassthrough,
		},
		{
			name:         "passthrough: docker",
			toolName:     "Bash",
			command:      "docker run -it ubuntu",
			wantDecision: DecisionPassthrough,
		},

		// ── File tools ──────────────────────────────

		{
			name:         "allow: read any file",
			toolName:     "Read",
			filePath:     "/any/path/anything.xyz",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: edit .go",
			toolName:     "Edit",
			filePath:     "/project/main.go",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: edit .dart",
			toolName:     "Edit",
			filePath:     "/project/lib/main.dart",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: edit .arb",
			toolName:     "Edit",
			filePath:     "/project/lib/l10n/app_en.arb",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: edit .xml",
			toolName:     "Edit",
			filePath:     "/project/web/sitemap.xml",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: write .ts",
			toolName:     "Write",
			filePath:     "/project/src/index.ts",
			wantDecision: DecisionAllow,
		},
		{
			name:         "allow: write .json",
			toolName:     "Write",
			filePath:     "/project/package.json",
			wantDecision: DecisionAllow,
		},
		{
			name:         "deny: write .env",
			toolName:     "Write",
			filePath:     "/project/.env",
			wantDecision: DecisionDeny,
		},
		{
			name:         "deny: write .pem",
			toolName:     "Write",
			filePath:     "/project/cert.pem",
			wantDecision: DecisionDeny,
		},
		{
			name:         "deny: write .key",
			toolName:     "Write",
			filePath:     "/project/private.key",
			wantDecision: DecisionDeny,
		},
		{
			name:         "passthrough: edit .env excluded",
			toolName:     "Edit",
			filePath:     "/project/.env",
			wantDecision: DecisionPassthrough,
		},
		{
			name:         "passthrough: edit unknown extension",
			toolName:     "Edit",
			filePath:     "/project/file.xyz",
			wantDecision: DecisionPassthrough,
		},
		{
			name:         "passthrough: write unknown extension",
			toolName:     "Write",
			filePath:     "/project/data.bin",
			wantDecision: DecisionPassthrough,
		},
		{
			name:         "ask: edit .lock",
			toolName:     "Edit",
			filePath:     "/project/pubspec.lock",
			wantDecision: DecisionAsk,
		},
		{
			name:         "ask: edit go.sum",
			toolName:     "Edit",
			filePath:     "/project/go.sum",
			wantDecision: DecisionAsk,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &hook.Input{
				ToolName: tt.toolName,
				ToolInput: hook.ToolInput{
					Command:  tt.command,
					FilePath: tt.filePath,
				},
			}

			result, _ := Evaluate(cfg, input)

			if result.Decision != tt.wantDecision {
				t.Errorf("decision = %q, want %q (reason: %q)",
					result.Decision, tt.wantDecision, result.Reason)
			}
		})
	}
}
