package config

import (
	"os"
	"path/filepath"
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
