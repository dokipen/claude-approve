package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseBasicConfig(t *testing.T) {
	toml := `
[audit]
audit_file = "/tmp/test-audit.json"
audit_level = "all"

[[deny]]
tool = "Bash"
command_regex = "^rm .*-rf"
reason = "Dangerous delete"

[[allow]]
tool = "Bash"
command_regex = "^git "
command_exclude_regex = "push.*--force"
reason = "Git commands"

[[allow]]
tool = "Read"
file_path_regex = "^/Users/test/"
reason = "Read workspace"

[[ask]]
tool = "Edit"
file_path_regex = "\\.lock$"
reason = "Editing lock files"

[[log]]
tool = "Bash"
command_regex = ".*"
reason = "Audit all bash"
`

	cfg, err := Parse(toml)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if cfg.Audit.AuditFile != "/tmp/test-audit.json" {
		t.Errorf("audit_file = %q, want /tmp/test-audit.json", cfg.Audit.AuditFile)
	}
	if cfg.Audit.AuditLevel != AuditAll {
		t.Errorf("audit_level = %q, want all", cfg.Audit.AuditLevel)
	}

	// Rules should be ordered: deny, ask, allow, log
	if len(cfg.Rules) != 5 {
		t.Fatalf("got %d rules, want 5", len(cfg.Rules))
	}

	expectations := []struct {
		ruleType RuleType
		tool     string
	}{
		{RuleDeny, "Bash"},
		{RuleAsk, "Edit"},
		{RuleAllow, "Bash"},
		{RuleAllow, "Read"},
		{RuleLog, "Bash"},
	}

	for i, exp := range expectations {
		if cfg.Rules[i].Type != exp.ruleType {
			t.Errorf("rule[%d].Type = %q, want %q", i, cfg.Rules[i].Type, exp.ruleType)
		}
		if cfg.Rules[i].Tool != exp.tool {
			t.Errorf("rule[%d].Tool = %q, want %q", i, cfg.Rules[i].Tool, exp.tool)
		}
	}
}

func TestParseDefaultAuditLevel(t *testing.T) {
	cfg, err := Parse(`
[[allow]]
tool = "Bash"
command_regex = ".*"
reason = "allow all"
`)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if cfg.Audit.AuditLevel != AuditMatched {
		t.Errorf("default audit_level = %q, want matched", cfg.Audit.AuditLevel)
	}
}

func TestParseInvalidAuditLevel(t *testing.T) {
	_, err := Parse(`
[audit]
audit_level = "bogus"
`)
	if err == nil {
		t.Error("expected error for invalid audit_level, got nil")
	}
}

func TestParseInvalidRegex(t *testing.T) {
	_, err := Parse(`
[[allow]]
tool = "Bash"
command_regex = "["
reason = "bad regex"
`)
	if err == nil {
		t.Error("expected error for invalid regex, got nil")
	}
}

func TestCompileRegexes(t *testing.T) {
	cfg, err := Parse(`
[[allow]]
tool = "Bash"
command_regex = "^flutter "
command_exclude_regex = "&&"
reason = "flutter"

[[allow]]
tool = "Read"
file_path_regex = "^/home/"
file_path_exclude_regex = "\\.secret"
reason = "read home"
`)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	r0 := cfg.Rules[0]
	if r0.CompiledCommand() == nil {
		t.Error("rule[0] command regex not compiled")
	}
	if r0.CompiledCommandExclude() == nil {
		t.Error("rule[0] command exclude regex not compiled")
	}

	r1 := cfg.Rules[1]
	if r1.CompiledFilePath() == nil {
		t.Error("rule[1] file path regex not compiled")
	}
	if r1.CompiledFilePathExclude() == nil {
		t.Error("rule[1] file path exclude regex not compiled")
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.toml")

	err := os.WriteFile(path, []byte(`
[[allow]]
tool = "Bash"
command_regex = "^echo "
reason = "echo"
`), 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(cfg.Rules) != 1 {
		t.Errorf("got %d rules, want 1", len(cfg.Rules))
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path.toml")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestWarnings(t *testing.T) {
	cases := []struct {
		name                string
		toml                string
		wantWarnings        int
		wantMessageContains string // if non-empty, first warning message must contain this substring
	}{
		{
			name: "anchored with caret — no warning",
			toml: `
[[deny]]
tool = "Write"
file_path_regex = "^/etc/"
reason = "system files"
`,
			wantWarnings: 0,
		},
		{
			name: `\A is not a valid anchor in RE2 — warning`,
			toml: `
[[allow]]
tool = "Read"
file_path_regex = "\\A/home/"
reason = "home dir"
`,
			wantWarnings: 1,
		},
		{
			name: "unanchored extension pattern — warning",
			toml: `
[[deny]]
tool = "Write"
file_path_regex = "\\.go$"
reason = "go files"
`,
			wantWarnings: 1,
		},
		{
			name: "unanchored directory name — warning",
			toml: `
[[allow]]
tool = "Read"
file_path_regex = "safe_dir"
reason = "safe directory"
`,
			wantWarnings: 1,
		},
		{
			name: "unanchored wildcard — warning",
			toml: `
[[ask]]
tool = "Edit"
file_path_regex = ".*"
reason = "all files"
`,
			wantWarnings: 1,
		},
		{
			name: "unanchored file_path_exclude_regex — warning",
			toml: `
[[allow]]
tool = "Edit"
file_path_regex = "^\\.go$"
file_path_exclude_regex = "\\.env"
reason = "go files excluding env"
`,
			wantWarnings: 1,
		},
		{
			name: "empty file_path_regex — no warning",
			toml: `
[[deny]]
tool = "Bash"
command_regex = "^rm "
reason = "dangerous delete"
`,
			wantWarnings: 0,
		},
		{
			name: "anchored alternation all branches — no warning",
			toml: `
[[deny]]
tool = "Write"
file_path_regex = "^/etc/|^/usr/"
reason = "system files"
`,
			wantWarnings: 0,
		},
		{
			name: "alternation with unanchored branch — warning",
			toml: `
[[deny]]
tool = "Write"
file_path_regex = "^/etc/|unanchored"
reason = "system files"
`,
			wantWarnings:        1,
			wantMessageContains: `branch: "unanchored"`,
		},
		{
			name: "alternation multi-branch partial anchor — warning",
			toml: `
[[deny]]
tool = "Write"
file_path_regex = "^/etc/|^/usr/|unanchored"
reason = "system files"
`,
			wantWarnings: 1,
		},
		{
			name: "grouped alternation — known false positive warning",
			toml: `
[[deny]]
tool = "Write"
file_path_regex = "^(etc|usr)/"
reason = "system dirs"
`,
			wantWarnings: 1,
		},
		{
			name: "pipe inside character class — known false positive warning",
			toml: `
[[deny]]
tool = "Write"
file_path_regex = "^foo[a|b]bar"
reason = "char class with pipe"
`,
			wantWarnings: 1,
		},
		{
			name: "trailing pipe in file_path_regex — warning names empty branch explicitly",
			toml: `
[[deny]]
tool = "Write"
file_path_regex = "^/etc/|"
reason = "system files"
`,
			wantWarnings:        1,
			wantMessageContains: "trailing |",
		},
		{
			name: "trailing pipe in file_path_exclude_regex — warning names empty branch explicitly",
			toml: `
[[allow]]
tool = "Read"
file_path_regex = "^/home/"
file_path_exclude_regex = "^/home/root|"
reason = "home but not root"
`,
			wantWarnings:        1,
			wantMessageContains: "trailing |",
		},
		{
			name: "anchored alternation in file_path_exclude_regex — no warning",
			toml: `
[[allow]]
tool = "Read"
file_path_regex = "^/home/"
file_path_exclude_regex = "^/home/root|^/home/admin"
reason = "home but not root"
`,
			wantWarnings: 0,
		},
		{
			name: "multiple rules — only unanchored ones warn",
			toml: `
[[deny]]
tool = "Write"
file_path_regex = "^/etc/"
reason = "system files"

[[allow]]
tool = "Read"
file_path_regex = "\\.log$"
reason = "log files"

[[ask]]
tool = "Edit"
file_path_regex = "\\A/home/"
reason = "home dir"
`,
			wantWarnings: 2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse(tc.toml)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}
			got := Warnings(cfg)
			if len(got) != tc.wantWarnings {
				t.Errorf("Warnings() returned %d warnings, want %d; got: %v", len(got), tc.wantWarnings, got)
			}
			if tc.wantMessageContains != "" && len(got) > 0 && !strings.Contains(got[0].Message, tc.wantMessageContains) {
				t.Errorf("Warnings()[0].Message = %q; want it to contain %q", got[0].Message, tc.wantMessageContains)
			}
		})
	}
}

func TestParseToolRegex(t *testing.T) {
	cfg, err := Parse(`
[[allow]]
tool_regex = "^mcp__workshop__"
reason = "Workshop MCP tools"
`)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(cfg.Rules))
	}
	r := cfg.Rules[0]
	if r.ToolRegex != "^mcp__workshop__" {
		t.Errorf("ToolRegex = %q, want %q", r.ToolRegex, "^mcp__workshop__")
	}
	if r.CompiledToolRegex() == nil {
		t.Error("tool regex not compiled")
	}
	if !r.CompiledToolRegex().MatchString("mcp__workshop__list_tracks") {
		t.Error("compiled regex should match mcp__workshop__list_tracks")
	}
}

func TestParseInvalidToolRegex(t *testing.T) {
	_, err := Parse(`
[[allow]]
tool_regex = "["
reason = "bad regex"
`)
	if err == nil {
		t.Error("expected error for invalid tool_regex, got nil")
	}
}

func TestParseBothToolAndToolRegex(t *testing.T) {
	_, err := Parse(`
[[allow]]
tool = "Bash"
tool_regex = "^Bash$"
reason = "both specified"
`)
	if err == nil {
		t.Error("expected error when both tool and tool_regex are set, got nil")
	}
}

func TestParseNeitherToolNorToolRegex(t *testing.T) {
	_, err := Parse(`
[[allow]]
command_regex = "^git "
reason = "no tool specified"
`)
	if err == nil {
		t.Error("expected error when neither tool nor tool_regex is set, got nil")
	}
}

func TestParseToolRegexWithInputConstraints(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{
			name: "tool_regex with command_regex rejected",
			config: `
[[allow]]
tool_regex = "^mcp__"
command_regex = "ls"
reason = "test"
`,
		},
		{
			name: "tool_regex with file_path_regex rejected",
			config: `
[[allow]]
tool_regex = "^mcp__"
file_path_regex = "/tmp"
reason = "test"
`,
		},
		{
			name: "tool_regex with command_exclude_regex rejected",
			config: `
[[allow]]
tool_regex = "^mcp__"
command_exclude_regex = "rm"
reason = "test"
`,
		},
		{
			name: "tool_regex with file_path_exclude_regex rejected",
			config: `
[[allow]]
tool_regex = "^mcp__"
file_path_exclude_regex = "/etc"
reason = "test"
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.config)
			if err == nil {
				t.Error("expected error for tool_regex with input constraints, got nil")
			}
		})
	}
}
