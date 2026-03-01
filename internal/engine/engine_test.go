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

func TestDenyBlocksBash(t *testing.T) {
	cfg := mustParse(t, `
[[deny]]
tool = "Bash"
command_regex = "^rm .*-rf"
reason = "Dangerous delete"
`)

	input := &hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "rm -rf /"},
	}

	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionDeny {
		t.Errorf("decision = %q, want deny", result.Decision)
	}
	if result.Reason != "Dangerous delete" {
		t.Errorf("reason = %q, want 'Dangerous delete'", result.Reason)
	}
}

func TestAllowApprovesBash(t *testing.T) {
	cfg := mustParse(t, `
[[allow]]
tool = "Bash"
command_regex = "^git "
reason = "Git commands"
`)

	input := &hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "git status"},
	}

	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionAllow {
		t.Errorf("decision = %q, want allow", result.Decision)
	}
}

func TestDenyTakesPrecedenceOverAllow(t *testing.T) {
	cfg := mustParse(t, `
[[deny]]
tool = "Bash"
command_regex = "^git push.*--force"
reason = "No force push"

[[allow]]
tool = "Bash"
command_regex = "^git "
reason = "Git commands"
`)

	input := &hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "git push --force origin main"},
	}

	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionDeny {
		t.Errorf("decision = %q, want deny (deny should take precedence)", result.Decision)
	}
}

func TestExcludeRegexPreventsMatch(t *testing.T) {
	cfg := mustParse(t, `
[[allow]]
tool = "Bash"
command_regex = "^flutter "
command_exclude_regex = "&&|;|\\||` + "`" + `"
reason = "Flutter without chaining"
`)

	// Should match (no chaining)
	input1 := &hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "flutter test"},
	}
	result1, _ := Evaluate(cfg, input1)
	if result1.Decision != DecisionAllow {
		t.Errorf("flutter test: decision = %q, want allow", result1.Decision)
	}

	// Should not match (has chaining)
	input2 := &hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "flutter test && rm -rf /"},
	}
	result2, _ := Evaluate(cfg, input2)
	if result2.Decision != DecisionPassthrough {
		t.Errorf("flutter test && rm: decision = %q, want passthrough", result2.Decision)
	}
}

func TestPassthroughWhenNoMatch(t *testing.T) {
	cfg := mustParse(t, `
[[allow]]
tool = "Bash"
command_regex = "^git "
reason = "Git"
`)

	input := &hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "npm install"},
	}

	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionPassthrough {
		t.Errorf("decision = %q, want passthrough", result.Decision)
	}
}

func TestReadFilePathMatch(t *testing.T) {
	cfg := mustParse(t, `
[[allow]]
tool = "Read"
file_path_regex = "^/Users/bob/src/"
reason = "Read workspace"
`)

	input := &hook.Input{
		ToolName:  "Read",
		ToolInput: hook.ToolInput{FilePath: "/Users/bob/src/project/main.go"},
	}

	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionAllow {
		t.Errorf("decision = %q, want allow", result.Decision)
	}
}

func TestReadFilePathExclude(t *testing.T) {
	cfg := mustParse(t, `
[[allow]]
tool = "Read"
file_path_regex = "^/Users/bob/"
file_path_exclude_regex = "\\.env"
reason = "Read but not env files"
`)

	input := &hook.Input{
		ToolName:  "Read",
		ToolInput: hook.ToolInput{FilePath: "/Users/bob/.env"},
	}

	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionPassthrough {
		t.Errorf("decision = %q, want passthrough (.env excluded)", result.Decision)
	}
}

func TestEditMatch(t *testing.T) {
	cfg := mustParse(t, `
[[allow]]
tool = "Edit"
file_path_regex = "\\.go$"
reason = "Edit Go files"
`)

	input := &hook.Input{
		ToolName:  "Edit",
		ToolInput: hook.ToolInput{FilePath: "/src/main.go"},
	}

	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionAllow {
		t.Errorf("decision = %q, want allow", result.Decision)
	}
}

func TestWriteMatch(t *testing.T) {
	cfg := mustParse(t, `
[[deny]]
tool = "Write"
file_path_regex = "\\.env"
reason = "Don't write env files"
`)

	input := &hook.Input{
		ToolName:  "Write",
		ToolInput: hook.ToolInput{FilePath: "/project/.env.local"},
	}

	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionDeny {
		t.Errorf("decision = %q, want deny", result.Decision)
	}
}

func TestAskDecision(t *testing.T) {
	cfg := mustParse(t, `
[[ask]]
tool = "Edit"
file_path_regex = "\\.lock$"
reason = "Lock files need confirmation"
`)

	input := &hook.Input{
		ToolName:  "Edit",
		ToolInput: hook.ToolInput{FilePath: "/project/pubspec.lock"},
	}

	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionAsk {
		t.Errorf("decision = %q, want ask", result.Decision)
	}
}

func TestLogRulesCollectedSeparately(t *testing.T) {
	cfg := mustParse(t, `
[[log]]
tool = "Bash"
command_regex = ".*"
reason = "Audit all bash"

[[allow]]
tool = "Bash"
command_regex = "^echo "
reason = "Echo allowed"
`)

	input := &hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "echo hello"},
	}

	result, logResults := Evaluate(cfg, input)

	// Permission decision should be allow (from allow rule)
	if result.Decision != DecisionAllow {
		t.Errorf("decision = %q, want allow", result.Decision)
	}

	// Log rule should fire separately
	if len(logResults) != 1 {
		t.Fatalf("got %d log results, want 1", len(logResults))
	}
	if logResults[0].Reason != "Audit all bash" {
		t.Errorf("log reason = %q, want 'Audit all bash'", logResults[0].Reason)
	}
}

func TestLogOnlyDoesNotAffectPermission(t *testing.T) {
	cfg := mustParse(t, `
[[log]]
tool = "Bash"
command_regex = ".*"
reason = "Audit"
`)

	input := &hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "anything"},
	}

	result, logResults := Evaluate(cfg, input)
	if result.Decision != DecisionPassthrough {
		t.Errorf("decision = %q, want passthrough (log shouldn't affect permission)", result.Decision)
	}
	if len(logResults) != 1 {
		t.Errorf("got %d log results, want 1", len(logResults))
	}
}

func TestUnknownToolPassthrough(t *testing.T) {
	cfg := mustParse(t, `
[[allow]]
tool = "Bash"
command_regex = ".*"
reason = "All bash"
`)

	input := &hook.Input{
		ToolName:  "Glob",
		ToolInput: hook.ToolInput{},
	}

	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionPassthrough {
		t.Errorf("decision = %q, want passthrough for unsupported tool", result.Decision)
	}
}

func TestMultipleDenyRulesFirstWins(t *testing.T) {
	cfg := mustParse(t, `
[[deny]]
tool = "Bash"
command_regex = "^rm "
reason = "No rm"

[[deny]]
tool = "Bash"
command_regex = "^rm -rf"
reason = "Especially no rm -rf"
`)

	input := &hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "rm -rf /"},
	}

	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionDeny {
		t.Errorf("decision = %q, want deny", result.Decision)
	}
	if result.Reason != "No rm" {
		t.Errorf("reason = %q, want 'No rm' (first deny should win)", result.Reason)
	}
}

func TestNoRegexMatchesAllForTool(t *testing.T) {
	cfg := mustParse(t, `
[[allow]]
tool = "Read"
reason = "Allow all reads"
`)

	input := &hook.Input{
		ToolName:  "Read",
		ToolInput: hook.ToolInput{FilePath: "/any/path"},
	}

	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionAllow {
		t.Errorf("decision = %q, want allow (no regex = match all)", result.Decision)
	}
}

// --- Compound command tests ---

func TestCompoundDenyTrumpsAllow(t *testing.T) {
	cfg := mustParse(t, `
[[deny]]
tool = "Bash"
command_regex = "^rm .*-rf"
reason = "Dangerous delete"

[[allow]]
tool = "Bash"
command_regex = "^git "
reason = "Git commands"
`)

	input := &hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "git status && rm -rf /"},
	}
	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionDeny {
		t.Errorf("decision = %q, want deny", result.Decision)
	}
	if !strings.Contains(result.Reason, "rm -rf /") {
		t.Errorf("reason = %q, should mention the offending sub-command", result.Reason)
	}
}

func TestCompoundAllAllowed(t *testing.T) {
	cfg := mustParse(t, `
[[allow]]
tool = "Bash"
command_regex = "^git "
reason = "Git commands"
`)

	input := &hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "git status && git log"},
	}
	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionAllow {
		t.Errorf("decision = %q, want allow", result.Decision)
	}
}

func TestCompoundAllowPlusPassthrough(t *testing.T) {
	cfg := mustParse(t, `
[[allow]]
tool = "Bash"
command_regex = "^git "
reason = "Git commands"
`)

	input := &hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "git status && npm install"},
	}
	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionPassthrough {
		t.Errorf("decision = %q, want passthrough (npm has no rule)", result.Decision)
	}
}

func TestCompoundAskTrumpsAllow(t *testing.T) {
	cfg := mustParse(t, `
[[ask]]
tool = "Bash"
command_regex = "^curl "
reason = "Network access needs confirmation"

[[allow]]
tool = "Bash"
command_regex = "^git "
reason = "Git commands"
`)

	input := &hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "git status && curl https://example.com"},
	}
	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionAsk {
		t.Errorf("decision = %q, want ask", result.Decision)
	}
}

func TestCompoundWithPipe(t *testing.T) {
	cfg := mustParse(t, `
[[allow]]
tool = "Bash"
command_regex = "^(cat|grep) "
reason = "Safe read commands"
`)

	input := &hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "cat file.txt | grep error"},
	}
	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionAllow {
		t.Errorf("decision = %q, want allow", result.Decision)
	}
}

func TestCompoundQuotedOperatorsNotSplit(t *testing.T) {
	cfg := mustParse(t, `
[[allow]]
tool = "Bash"
command_regex = "^echo "
reason = "Echo allowed"
`)

	input := &hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: `echo "a && b"`},
	}
	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionAllow {
		t.Errorf("decision = %q, want allow (quoted && should not split)", result.Decision)
	}
}

func TestCompoundSemicolon(t *testing.T) {
	cfg := mustParse(t, `
[[deny]]
tool = "Bash"
command_regex = "^rm .*-rf"
reason = "Dangerous delete"

[[allow]]
tool = "Bash"
command_regex = "^ls"
reason = "List allowed"
`)

	input := &hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "ls; rm -rf /"},
	}
	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionDeny {
		t.Errorf("decision = %q, want deny", result.Decision)
	}
}

func TestCompoundLogRulesFromAllSubcommands(t *testing.T) {
	cfg := mustParse(t, `
[[log]]
tool = "Bash"
command_regex = ".*"
reason = "Audit all bash"

[[allow]]
tool = "Bash"
command_regex = "^(git|echo) "
reason = "Safe commands"
`)

	input := &hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "git status && echo hello"},
	}
	result, logResults := Evaluate(cfg, input)
	if result.Decision != DecisionAllow {
		t.Errorf("decision = %q, want allow", result.Decision)
	}
	if len(logResults) != 2 {
		t.Errorf("got %d log results, want 2 (one per sub-command)", len(logResults))
	}
}

func TestSingleCommandUnchanged(t *testing.T) {
	cfg := mustParse(t, `
[[allow]]
tool = "Bash"
command_regex = "^git "
reason = "Git commands"
`)

	input := &hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "git status"},
	}
	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionAllow {
		t.Errorf("decision = %q, want allow", result.Decision)
	}
	if strings.Contains(result.Reason, "[in:") {
		t.Errorf("reason = %q, should not have [in:] annotation for single command", result.Reason)
	}
}

func TestNonBashToolUnaffected(t *testing.T) {
	cfg := mustParse(t, `
[[allow]]
tool = "Read"
file_path_regex = ".*"
reason = "Allow all reads"
`)

	input := &hook.Input{
		ToolName:  "Read",
		ToolInput: hook.ToolInput{FilePath: "/some/path && /other/path"},
	}
	result, _ := Evaluate(cfg, input)
	if result.Decision != DecisionAllow {
		t.Errorf("decision = %q, want allow (Read should not be split)", result.Decision)
	}
}
