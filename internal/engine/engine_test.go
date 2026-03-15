package engine

import (
	"strings"
	"testing"

	"github.com/dokipen/claude-approve/internal/config"
	"github.com/dokipen/claude-approve/internal/hook"
)

func mustParse(t *testing.T, toml string) *config.Config {
	t.Helper()
	cfg, err := config.Parse(toml)
	if err != nil {
		t.Fatalf("config.Parse failed: %v", err)
	}
	return cfg
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name               string
		config             string
		toolName           string
		command            string // Bash
		filePath           string // Read/Edit/Write
		wantDecision       Decision
		wantReason         string // exact match (empty = skip)
		wantReasonContains string // substring match (empty = skip)
		wantReasonExcludes string // must NOT contain (empty = skip)
		wantLogCount       int    // -1 = skip check
	}{
		// --- Basic rule matching ---
		{
			name: "deny blocks bash",
			config: `
[[deny]]
tool = "Bash"
command_regex = "^rm .*-rf"
reason = "Dangerous delete"`,
			toolName:     "Bash",
			command:      "rm -rf /",
			wantDecision: DecisionDeny,
			wantReason:   "Dangerous delete",
			wantLogCount: -1,
		},
		{
			name: "allow approves bash",
			config: `
[[allow]]
tool = "Bash"
command_regex = "^git "
reason = "Git commands"`,
			toolName:     "Bash",
			command:      "git status",
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},
		{
			name: "deny takes precedence over allow",
			config: `
[[deny]]
tool = "Bash"
command_regex = "^git push.*--force"
reason = "No force push"

[[allow]]
tool = "Bash"
command_regex = "^git "
reason = "Git commands"`,
			toolName:     "Bash",
			command:      "git push --force origin main",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},
		{
			name: "passthrough when no match",
			config: `
[[allow]]
tool = "Bash"
command_regex = "^git "
reason = "Git"`,
			toolName:     "Bash",
			command:      "npm install",
			wantDecision: DecisionPassthrough,
			wantLogCount: -1,
		},
		{
			name: "multiple deny rules first wins",
			config: `
[[deny]]
tool = "Bash"
command_regex = "^rm "
reason = "No rm"

[[deny]]
tool = "Bash"
command_regex = "^rm -rf"
reason = "Especially no rm -rf"`,
			toolName:     "Bash",
			command:      "rm -rf /",
			wantDecision: DecisionDeny,
			wantReason:   "No rm",
			wantLogCount: -1,
		},
		{
			name: "unknown tool passthrough",
			config: `
[[allow]]
tool = "Bash"
command_regex = ".*"
reason = "All bash"`,
			toolName:     "Glob",
			wantDecision: DecisionPassthrough,
			wantLogCount: -1,
		},
		{
			name: "ask decision",
			config: `
[[ask]]
tool = "Edit"
file_path_regex = "\\.lock$"
reason = "Lock files need confirmation"`,
			toolName:     "Edit",
			filePath:     "/project/pubspec.lock",
			wantDecision: DecisionAsk,
			wantLogCount: -1,
		},

		// --- File path matching ---
		{
			name: "read file path match",
			config: `
[[allow]]
tool = "Read"
file_path_regex = "^/Users/bob/src/"
reason = "Read workspace"`,
			toolName:     "Read",
			filePath:     "/Users/bob/src/project/main.go",
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},
		{
			name: "read file path exclude",
			config: `
[[allow]]
tool = "Read"
file_path_regex = "^/Users/bob/"
file_path_exclude_regex = "\\.env"
reason = "Read but not env files"`,
			toolName:     "Read",
			filePath:     "/Users/bob/.env",
			wantDecision: DecisionPassthrough,
			wantLogCount: -1,
		},
		{
			name: "edit match",
			config: `
[[allow]]
tool = "Edit"
file_path_regex = "\\.go$"
reason = "Edit Go files"`,
			toolName:     "Edit",
			filePath:     "/src/main.go",
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},
		{
			name: "write deny",
			config: `
[[deny]]
tool = "Write"
file_path_regex = "\\.env"
reason = "Don't write env files"`,
			toolName:     "Write",
			filePath:     "/project/.env.local",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},
		{
			name: "no regex matches all for tool",
			config: `
[[allow]]
tool = "Read"
reason = "Allow all reads"`,
			toolName:     "Read",
			filePath:     "/any/path",
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},

		// --- Exclude regex ---
		{
			name: "exclude regex allows simple command",
			config: `
[[allow]]
tool = "Bash"
command_regex = "^flutter "
command_exclude_regex = "&&|;|\\||` + "`" + `"
reason = "Flutter without chaining"`,
			toolName:     "Bash",
			command:      "flutter test",
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},
		{
			name: "exclude regex blocks chained command",
			config: `
[[allow]]
tool = "Bash"
command_regex = "^flutter "
command_exclude_regex = "&&|;|\\||` + "`" + `"
reason = "Flutter without chaining"`,
			toolName:     "Bash",
			command:      "flutter test && rm -rf /",
			wantDecision: DecisionPassthrough,
			wantLogCount: -1,
		},

		// --- Log rules ---
		{
			name: "log rules collected separately",
			config: `
[[log]]
tool = "Bash"
command_regex = ".*"
reason = "Audit all bash"

[[allow]]
tool = "Bash"
command_regex = "^echo "
reason = "Echo allowed"`,
			toolName:     "Bash",
			command:      "echo hello",
			wantDecision: DecisionAllow,
			wantLogCount: 1,
		},
		{
			name: "log only does not affect permission",
			config: `
[[log]]
tool = "Bash"
command_regex = ".*"
reason = "Audit"`,
			toolName:     "Bash",
			command:      "anything",
			wantDecision: DecisionPassthrough,
			wantLogCount: 1,
		},

		// --- Compound commands ---
		{
			name: "compound: deny trumps allow",
			config: `
[[deny]]
tool = "Bash"
command_regex = "^rm .*-rf"
reason = "Dangerous delete"

[[allow]]
tool = "Bash"
command_regex = "^git "
reason = "Git commands"`,
			toolName:           "Bash",
			command:            "git status && rm -rf /",
			wantDecision:       DecisionDeny,
			wantReasonContains: "rm -rf /",
			wantLogCount:       -1,
		},
		{
			name: "compound: all allowed",
			config: `
[[allow]]
tool = "Bash"
command_regex = "^git "
reason = "Git commands"`,
			toolName:     "Bash",
			command:      "git status && git log",
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},
		{
			name: "compound: allow + passthrough = passthrough",
			config: `
[[allow]]
tool = "Bash"
command_regex = "^git "
reason = "Git commands"`,
			toolName:     "Bash",
			command:      "git status && npm install",
			wantDecision: DecisionPassthrough,
			wantLogCount: -1,
		},
		{
			name: "compound: ask trumps allow",
			config: `
[[ask]]
tool = "Bash"
command_regex = "^curl "
reason = "Network access needs confirmation"

[[allow]]
tool = "Bash"
command_regex = "^git "
reason = "Git commands"`,
			toolName:     "Bash",
			command:      "git status && curl https://example.com",
			wantDecision: DecisionAsk,
			wantLogCount: -1,
		},
		{
			name: "compound: pipe",
			config: `
[[allow]]
tool = "Bash"
command_regex = "^(cat|grep) "
reason = "Safe read commands"`,
			toolName:     "Bash",
			command:      "cat file.txt | grep error",
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},
		{
			name: "compound: quoted operators not split",
			config: `
[[allow]]
tool = "Bash"
command_regex = "^echo "
reason = "Echo allowed"`,
			toolName:     "Bash",
			command:      `echo "a && b"`,
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},
		{
			name: "compound: semicolon with deny",
			config: `
[[deny]]
tool = "Bash"
command_regex = "^rm .*-rf"
reason = "Dangerous delete"

[[allow]]
tool = "Bash"
command_regex = "^ls"
reason = "List allowed"`,
			toolName:     "Bash",
			command:      "ls; rm -rf /",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},
		{
			name: "compound: log rules from all subcommands",
			config: `
[[log]]
tool = "Bash"
command_regex = ".*"
reason = "Audit all bash"

[[allow]]
tool = "Bash"
command_regex = "^(git|echo) "
reason = "Safe commands"`,
			toolName:     "Bash",
			command:      "git status && echo hello",
			wantDecision: DecisionAllow,
			wantLogCount: 2,
		},
		{
			name: "compound: single command no annotation",
			config: `
[[allow]]
tool = "Bash"
command_regex = "^git "
reason = "Git commands"`,
			toolName:           "Bash",
			command:            "git status",
			wantDecision:       DecisionAllow,
			wantReasonExcludes: "[in:",
			wantLogCount:       -1,
		},
		{
			name: "compound: non-bash tool unaffected",
			config: `
[[allow]]
tool = "Read"
file_path_regex = ".*"
reason = "Allow all reads"`,
			toolName:     "Read",
			filePath:     "/some/path && /other/path",
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},

		// --- Variable assignment stripping ---
		{
			name: "var assignment: deny rule matches gh inside REPO=$(gh ...)",
			config: `
[[deny]]
tool = "Bash"
command_regex = "^gh "
reason = "No gh commands"`,
			toolName:           "Bash",
			command:            `REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner) && gh issue list`,
			wantDecision:       DecisionDeny,
			wantReasonContains: "No gh commands",
			wantLogCount:       -1,
		},
		{
			name: "var assignment: allow rule matches cat inside PLAN_CONTENT=$(cat ...)",
			config: `
[[allow]]
tool = "Bash"
command_regex = "^(cat|echo) "
reason = "Safe read commands"`,
			toolName:     "Bash",
			command:      `PLAN_CONTENT=$(cat /path/to/PLAN.md) && echo done`,
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},
		{
			name: "var assignment: env prefix stripped before deny match",
			config: `
[[deny]]
tool = "Bash"
command_regex = "^rm .*-rf"
reason = "Dangerous delete"`,
			toolName:           "Bash",
			command:            `FOO=bar rm -rf /`,
			wantDecision:       DecisionDeny,
			wantReason:         "Dangerous delete",
			wantLogCount:       -1,
		},
		{
			name: "var assignment: compound with assignment deny trumps allow",
			config: `
[[deny]]
tool = "Bash"
command_regex = "^rm .*-rf"
reason = "Dangerous delete"

[[allow]]
tool = "Bash"
command_regex = "^echo "
reason = "Echo allowed"`,
			toolName:           "Bash",
			command:            `DANGEROUS=$(rm -rf /) && echo done`,
			wantDecision:       DecisionDeny,
			wantReasonContains: "Dangerous delete",
			wantLogCount:       -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := mustParse(t, tt.config)

			input := &hook.Input{
				ToolName: tt.toolName,
				ToolInput: hook.ToolInput{
					Command:  tt.command,
					FilePath: tt.filePath,
				},
			}

			result, logResults := Evaluate(cfg, input)

			if result.Decision != tt.wantDecision {
				t.Errorf("decision = %q, want %q", result.Decision, tt.wantDecision)
			}
			if tt.wantReason != "" && result.Reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", result.Reason, tt.wantReason)
			}
			if tt.wantReasonContains != "" && !strings.Contains(result.Reason, tt.wantReasonContains) {
				t.Errorf("reason = %q, want it to contain %q", result.Reason, tt.wantReasonContains)
			}
			if tt.wantReasonExcludes != "" && strings.Contains(result.Reason, tt.wantReasonExcludes) {
				t.Errorf("reason = %q, should not contain %q", result.Reason, tt.wantReasonExcludes)
			}
			if tt.wantLogCount >= 0 && len(logResults) != tt.wantLogCount {
				t.Errorf("got %d log results, want %d", len(logResults), tt.wantLogCount)
			}
		})
	}
}
