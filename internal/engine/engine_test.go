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
		filePath           string // Read/Edit/Write/Update
		pattern            string // Grep/Glob
		path               string // Grep/Glob
		cwd                string // effective working directory
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
			toolName:     "Unknown",
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
reason = "No gh commands"

[[allow]]
tool = "Bash"
command_regex = "^echo "
reason = "Echo allowed"`,
			toolName:           "Bash",
			command:            `REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner) && echo $REPO`,
			wantDecision:       DecisionDeny,
			wantReasonContains: "No gh commands",
			wantLogCount:       -1,
		},
		{
			name: "var assignment: pure assignment extracts inner command",
			config: `
[[deny]]
tool = "Bash"
command_regex = "^gh "
reason = "No gh commands"`,
			toolName:           "Bash",
			command:            `RESULT=$(gh repo view --json name)`,
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

		// --- Search and Update tools ---

		// Grep tests
		{
			name: "grep-allow",
			config: `
[[allow]]
tool = "Grep"
file_path_regex = "\\.go$"
reason = "Grep Go files"`,
			toolName:     "Grep",
			path:         "/src/main.go",
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},
		{
			name: "grep-deny-path",
			config: `
[[deny]]
tool = "Grep"
file_path_regex = "/etc"
reason = "No grep in /etc"`,
			toolName:     "Grep",
			path:         "/etc/shadow",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},
		{
			name: "grep-tool-name-only",
			config: `
[[allow]]
tool = "Grep"
reason = "Allow all grep"`,
			toolName:     "Grep",
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},
		{
			name: "grep-exclude",
			config: `
[[allow]]
tool = "Grep"
file_path_regex = "."
file_path_exclude_regex = "vendor/"
reason = "Grep non-vendor"`,
			toolName:     "Grep",
			path:         "vendor/lib.go",
			wantDecision: DecisionPassthrough,
			wantLogCount: -1,
		},
		{
			name: "grep-no-match",
			config: `
[[allow]]
tool = "Grep"
file_path_regex = "\\.py$"
reason = "Grep Python files"`,
			toolName:     "Grep",
			path:         "/src/main.go",
			pattern:      "func",
			wantDecision: DecisionPassthrough,
			wantLogCount: -1,
		},

		// Glob tests
		{
			name: "glob-allow",
			config: `
[[allow]]
tool = "Glob"
file_path_regex = "/src"
reason = "Glob in src"`,
			toolName:     "Glob",
			path:         "/src",
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},
		{
			name: "glob-deny-path",
			config: `
[[deny]]
tool = "Glob"
file_path_regex = "/etc"
reason = "No glob in /etc"`,
			toolName:     "Glob",
			path:         "/etc",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},
		{
			name: "glob-tool-name-only",
			config: `
[[allow]]
tool = "Glob"
reason = "Allow all glob"`,
			toolName:     "Glob",
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},
		{
			name: "glob-exclude",
			config: `
[[allow]]
tool = "Glob"
file_path_regex = "."
file_path_exclude_regex = "node_modules"
reason = "Glob non-node_modules"`,
			toolName:     "Glob",
			path:         "node_modules",
			wantDecision: DecisionPassthrough,
			wantLogCount: -1,
		},
		{
			name: "glob-pattern-does-not-bypass-deny",
			config: `
[[deny]]
tool = "Glob"
file_path_regex = "/etc"
file_path_exclude_regex = "safe_dir"
reason = "No glob in /etc"`,
			toolName:     "Glob",
			path:         "/etc/shadow",
			pattern:      "safe_dir",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},
		{
			name: "glob-pattern-field-ignored-by-file-path-regex",
			config: `
[[allow]]
tool = "Glob"
file_path_regex = "\\.go$"
reason = "Glob Go files"`,
			toolName:     "Glob",
			path:         "/etc/passwd",
			pattern:      "main.go",
			wantDecision: DecisionPassthrough,
			wantLogCount: -1,
		},
		{
			name: "glob-empty-path-sensitive-pattern",
			config: `
[[deny]]
tool = "Glob"
file_path_regex = "/etc"
reason = "No glob in /etc"`,
			toolName:     "Glob",
			path:         "",
			pattern:      "/etc/shadow",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},
		{
			name: "grep-empty-path-sensitive-pattern",
			config: `
[[deny]]
tool = "Grep"
file_path_regex = "(?i)/etc"
reason = "No grep in /etc"`,
			toolName:     "Grep",
			path:         "",
			pattern:      "/etc/shadow",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},
		{
			name: "search-empty-path-sensitive-pattern",
			config: `
[[deny]]
tool = "Search"
file_path_regex = "(?i)/etc"
reason = "No search in /etc"`,
			toolName:     "Search",
			path:         "",
			pattern:      "/etc/shadow",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},
		{
			name: "glob-empty-path-benign-pattern",
			config: `
[[deny]]
tool = "Glob"
file_path_regex = "(?i)/etc"
reason = "No glob in /etc"`,
			toolName:     "Glob",
			path:         "",
			pattern:      "*.go",
			wantDecision: DecisionPassthrough,
			wantLogCount: -1,
		},
		{
			name: "glob-empty-path-both-fields-match",
			config: `
[[deny]]
tool = "Glob"
file_path_regex = "(?i)/etc"
reason = "No glob in /etc"`,
			toolName:     "Glob",
			path:         "/etc",
			pattern:      "/etc/shadow",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},
		{
			// Verify that file_path_exclude_regex does not suppress a deny rule
			// when path is empty and pattern contains the excluded term.
			// An agent must not be able to craft pattern to escape a deny rule.
			name: "glob-empty-path-exclude-does-not-suppress-deny",
			config: `
[[deny]]
tool = "Glob"
file_path_regex = "/etc"
file_path_exclude_regex = "shadow"
reason = "No glob in /etc"`,
			toolName:     "Glob",
			path:         "",
			pattern:      "/etc/shadow",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},
		{
			// Whitespace-only path is treated as empty: deny fires on pattern.
			name: "glob-whitespace-path-sensitive-pattern",
			config: `
[[deny]]
tool = "Glob"
file_path_regex = "/etc"
reason = "No glob in /etc"`,
			toolName:     "Glob",
			path:         "   ",
			pattern:      "/etc/shadow",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},

		// Cwd evaluation when path is empty
		{
			name:         "glob-empty-path-sensitive-cwd",
			toolName:     "Glob",
			path:         "",
			pattern:      "*.go",
			cwd:          "/etc/shadow",
			config:       "[[deny]]\ntool = \"Glob\"\nreason = \"no etc\"\nfile_path_regex = \"/etc\"",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},
		{
			name:         "grep-empty-path-sensitive-cwd",
			toolName:     "Grep",
			path:         "",
			pattern:      "TODO",
			cwd:          "/etc/secret",
			config:       "[[deny]]\ntool = \"Grep\"\nreason = \"no etc\"\nfile_path_regex = \"/etc\"",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},
		{
			name:         "search-empty-path-sensitive-cwd",
			toolName:     "Search",
			path:         "",
			pattern:      "TODO",
			cwd:          "/etc/secret",
			config:       "[[deny]]\ntool = \"Search\"\nreason = \"no etc\"\nfile_path_regex = \"/etc\"",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},
		{
			name:         "glob-empty-path-benign-cwd",
			toolName:     "Glob",
			path:         "",
			pattern:      "*.go",
			cwd:          "/home/user/project",
			config:       "[[deny]]\ntool = \"Glob\"\nreason = \"no etc\"\nfile_path_regex = \"/etc\"",
			wantDecision: DecisionPassthrough,
			wantLogCount: -1,
		},
		{
			name:         "glob-whitespace-path-sensitive-cwd",
			toolName:     "Glob",
			path:         "   ",
			pattern:      "*.go",
			cwd:          "/etc/shadow",
			config:       "[[deny]]\ntool = \"Glob\"\nreason = \"no etc\"\nfile_path_regex = \"/etc\"",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},
		{
			name:         "glob-nonempty-path-cwd-irrelevant",
			toolName:     "Glob",
			path:         "/home/user",
			pattern:      "*.go",
			cwd:          "/etc/shadow",
			config:       "[[deny]]\ntool = \"Glob\"\nreason = \"no etc\"\nfile_path_regex = \"/etc\"",
			wantDecision: DecisionPassthrough,
			wantLogCount: -1,
		},
		{
			// isExcluded only checks path/cwd against file_path_regex (via matchesInput),
			// then checks path against file_path_exclude_regex. It does NOT check Cwd
			// against file_path_exclude_regex. So even though Cwd matches the exclude
			// pattern, the rule still fires and the decision is Deny.
			name:         "glob-empty-path-cwd-not-checked-by-exclude",
			toolName:     "Glob",
			path:         "",
			pattern:      "*.go",
			cwd:          "/etc/shadow",
			config:       "[[deny]]\ntool = \"Glob\"\nreason = \"no etc\"\nfile_path_regex = \"/etc\"\nfile_path_exclude_regex = \"/etc/shadow\"",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},
		{
			// An absent Cwd (both path and cwd are empty) must not cause a spurious
			// match against a deny rule whose file_path_regex requires "/etc".
			name:         "glob-empty-path-empty-cwd-passthrough",
			toolName:     "Glob",
			path:         "",
			pattern:      "*.go",
			cwd:          "",
			config:       "[[deny]]\ntool = \"Glob\"\nreason = \"no etc\"\nfile_path_regex = \"/etc\"",
			wantDecision: DecisionPassthrough,
			wantLogCount: -1,
		},

		// Search tests
		{
			name: "search-allow",
			config: `
[[allow]]
tool = "Search"
file_path_regex = "\\.go$"
reason = "Search Go files"`,
			toolName:     "Search",
			path:         "/src/main.go",
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},
		{
			name: "search-deny-path",
			config: `
[[deny]]
tool = "Search"
file_path_regex = "/etc"
reason = "No search in /etc"`,
			toolName:     "Search",
			path:         "/etc/shadow",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},
		{
			name: "search-tool-name-only",
			config: `
[[allow]]
tool = "Search"
reason = "Allow all search"`,
			toolName:     "Search",
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},
		{
			name: "search-exclude",
			config: `
[[allow]]
tool = "Search"
file_path_regex = "."
file_path_exclude_regex = "vendor/"
reason = "Search non-vendor"`,
			toolName:     "Search",
			path:         "vendor/lib.go",
			wantDecision: DecisionPassthrough,
			wantLogCount: -1,
		},
		{
			name: "search-no-match",
			config: `
[[allow]]
tool = "Search"
file_path_regex = "\\.py$"
reason = "Search Python files"`,
			toolName:     "Search",
			path:         "/src/main.go",
			pattern:      "func",
			wantDecision: DecisionPassthrough,
			wantLogCount: -1,
		},
		{
			name: "search-pattern-does-not-bypass-deny",
			config: `
[[deny]]
tool = "Search"
file_path_regex = "/etc"
file_path_exclude_regex = "/etc/safe/"
reason = "No search in /etc"`,
			toolName:     "Search",
			path:         "/etc/shadow",
			pattern:      "/etc/safe/",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},
		{
			name: "search-pattern-field-ignored-by-file-path-regex",
			config: `
[[allow]]
tool = "Search"
file_path_regex = "\\.go$"
reason = "Search Go files"`,
			toolName:     "Search",
			path:         "/etc/passwd",
			pattern:      "main.go",
			wantDecision: DecisionPassthrough,
			wantLogCount: -1,
		},

		{
			name: "grep-pattern-does-not-bypass-deny",
			config: `
[[deny]]
tool = "Grep"
file_path_regex = "/etc"
file_path_exclude_regex = "safe_dir"
reason = "No grep in /etc"`,
			toolName:     "Grep",
			path:         "/etc/shadow",
			pattern:      "safe_dir",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},
		{
			name: "grep-pattern-field-ignored-by-file-path-regex",
			config: `
[[allow]]
tool = "Grep"
file_path_regex = "\\.go$"
reason = "Grep Go files"`,
			toolName:     "Grep",
			path:         "/etc/passwd",
			pattern:      "main.go",
			wantDecision: DecisionPassthrough,
			wantLogCount: -1,
		},

		// Update tests
		{
			name: "update-allow",
			config: `
[[allow]]
tool = "Update"
file_path_regex = "\\.go$"
reason = "Update Go files"`,
			toolName:     "Update",
			filePath:     "/src/main.go",
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},
		{
			name: "update-deny",
			config: `
[[deny]]
tool = "Update"
file_path_regex = "\\.env"
reason = "No update env files"`,
			toolName:     "Update",
			filePath:     ".env",
			wantDecision: DecisionDeny,
			wantLogCount: -1,
		},
		{
			name: "update-tool-name-only",
			config: `
[[allow]]
tool = "Update"
reason = "Allow all updates"`,
			toolName:     "Update",
			filePath:     "/any/file.txt",
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},
		{
			name: "update-exclude",
			config: `
[[allow]]
tool = "Update"
file_path_regex = "."
file_path_exclude_regex = "vendor/"
reason = "Update non-vendor"`,
			toolName:     "Update",
			filePath:     "vendor/lib.go",
			wantDecision: DecisionPassthrough,
			wantLogCount: -1,
		},

		// --- tool_regex matching ---
		{
			name: "tool_regex: match MCP tool",
			config: `
[[allow]]
tool_regex = "^mcp__workshop__"
reason = "Workshop MCP tools"`,
			toolName:     "mcp__workshop__workshop_list_tracks",
			wantDecision: DecisionAllow,
			wantReason:   "Workshop MCP tools",
			wantLogCount: -1,
		},
		{
			name: "tool_regex: no match",
			config: `
[[allow]]
tool_regex = "^mcp__workshop__"
reason = "Workshop MCP tools"`,
			toolName:     "mcp__ai_cli__run",
			wantDecision: DecisionPassthrough,
			wantLogCount: -1,
		},
		{
			name: "tool_regex: deny MCP tool",
			config: `
[[deny]]
tool_regex = "^mcp__dangerous__"
reason = "Deny dangerous MCP"`,
			toolName:     "mcp__dangerous__delete_everything",
			wantDecision: DecisionDeny,
			wantReason:   "Deny dangerous MCP",
			wantLogCount: -1,
		},
		{
			name: "tool_regex: deny takes precedence over allow",
			config: `
[[deny]]
tool_regex = "^mcp__workshop__workshop_delete"
reason = "No deleting"

[[allow]]
tool_regex = "^mcp__workshop__"
reason = "Workshop MCP tools"`,
			toolName:     "mcp__workshop__workshop_delete_track",
			wantDecision: DecisionDeny,
			wantReason:   "No deleting",
			wantLogCount: -1,
		},
		{
			name: "tool_regex: WebFetch allow",
			config: `
[[allow]]
tool_regex = "^WebFetch$"
reason = "Web fetch allowed"`,
			toolName:     "WebFetch",
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},
		{
			name: "tool_regex: WebSearch allow",
			config: `
[[allow]]
tool_regex = "^WebSearch$"
reason = "Web search allowed"`,
			toolName:     "WebSearch",
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},
		{
			name: "tool_regex: catch-all MCP",
			config: `
[[allow]]
tool_regex = "^mcp__"
reason = "All MCP tools"`,
			toolName:     "mcp__ai_cli_mcp__get_result",
			wantDecision: DecisionAllow,
			wantLogCount: -1,
		},
		{
			name: "tool_regex: log rule for MCP tools",
			config: `
[[log]]
tool_regex = "^mcp__"
reason = "Audit MCP calls"

[[allow]]
tool_regex = "^mcp__workshop__"
reason = "Workshop allowed"`,
			toolName:     "mcp__workshop__workshop_list_tracks",
			wantDecision: DecisionAllow,
			wantLogCount: 1,
		},
		{
			name: "tool_regex: mixed exact and regex rules",
			config: `
[[allow]]
tool = "Bash"
command_regex = "^git "
reason = "Git commands"

[[allow]]
tool_regex = "^mcp__workshop__"
reason = "Workshop MCP"`,
			toolName:     "Bash",
			command:      "git status",
			wantDecision: DecisionAllow,
			wantReason:   "Git commands",
			wantLogCount: -1,
		},

		// --- Generic tool (exact tool match, no constraints) ---
		{
			name: "generic tool: exact match with no constraints",
			config: `
[[allow]]
tool = "WebSearch"
reason = "Allow web search"`,
			toolName:     "WebSearch",
			wantDecision: DecisionAllow,
			wantReason:   "Allow web search",
			wantLogCount: -1,
		},
		{
			name: "generic tool: exact match does not cross-match",
			config: `
[[allow]]
tool = "WebSearch"
reason = "Allow web search"`,
			toolName:     "WebFetch",
			wantDecision: DecisionPassthrough,
			wantLogCount: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := mustParse(t, tt.config)

			input := &hook.Input{
				ToolName: tt.toolName,
				Cwd:      tt.cwd,
				ToolInput: hook.ToolInput{
					Command:  tt.command,
					FilePath: tt.filePath,
					Pattern:  tt.pattern,
					Path:     tt.path,
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
