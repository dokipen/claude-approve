package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dokipen/claude-approve/internal/config"
	"github.com/dokipen/claude-approve/internal/engine"
	"github.com/dokipen/claude-approve/internal/hook"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name      string
		level     config.AuditLevel
		fileFn    func(tmpdir string) string // returns the audit file path
		wantNil   bool
		wantErr   bool
		setupHome bool // if true, set HOME to tmpdir for ~ expansion
	}{
		{
			name:    "off returns nil",
			level:   config.AuditOff,
			fileFn:  func(d string) string { return filepath.Join(d, "audit.jsonl") },
			wantNil: true,
		},
		{
			name:    "empty file returns nil",
			level:   config.AuditAll,
			fileFn:  func(string) string { return "" },
			wantNil: true,
		},
		{
			name:   "absolute path creates file",
			level:  config.AuditAll,
			fileFn: func(d string) string { return filepath.Join(d, "audit.jsonl") },
		},
		{
			name:      "tilde expansion creates file",
			level:     config.AuditAll,
			fileFn:    func(string) string { return "~/.claude/audit.jsonl" },
			setupHome: true,
		},
		{
			name:      "tilde expansion with nested dirs",
			level:     config.AuditAll,
			fileFn:    func(string) string { return "~/.claude/logs/deep/audit.jsonl" },
			setupHome: true,
		},
		{
			name:   "creates parent directories",
			level:  config.AuditAll,
			fileFn: func(d string) string { return filepath.Join(d, "sub", "dir", "audit.jsonl") },
		},
		{
			name:   "existing directory works",
			level:  config.AuditMatched,
			fileFn: func(d string) string { return filepath.Join(d, "audit.jsonl") },
		},
		{
			name:      "tilde path traversal blocked",
			level:     config.AuditAll,
			fileFn:    func(string) string { return "~/../../etc/shadow" },
			setupHome: true,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpdir := t.TempDir()
			auditFile := tt.fileFn(tmpdir)

			if tt.setupHome {
				t.Setenv("HOME", tmpdir)
			}

			cfg := &config.Audit{
				AuditFile:  auditFile,
				AuditLevel: tt.level,
			}

			logger, err := NewLogger(cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantNil {
				if logger != nil {
					t.Fatal("expected nil logger")
				}
				return
			}

			if logger == nil {
				t.Fatal("expected non-nil logger")
			}
			defer logger.Close()

			// Verify the file was created
			var expectedPath string
			if strings.HasPrefix(auditFile, "~/") {
				expectedPath = filepath.Join(tmpdir, auditFile[2:])
			} else {
				expectedPath = auditFile
			}
			if _, err := os.Stat(expectedPath); err != nil {
				t.Fatalf("audit file not created at %s: %v", expectedPath, err)
			}
		})
	}
}

func TestNewLogger_tildeOtherUser_notExpanded(t *testing.T) {
	// ~otheruser/path should NOT be expanded — it doesn't start with ~/
	// This will fail to create the file (no such directory), which is expected.
	// The key assertion is that it does NOT attempt home dir expansion.
	tmpdir := t.TempDir()
	path := filepath.Join(tmpdir, "~weird", "audit.jsonl")

	logger, err := NewLogger(&config.Audit{
		AuditFile:  path,
		AuditLevel: config.AuditAll,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer logger.Close()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created at %s: %v", path, err)
	}
}

func TestNewLogger_directoryPermissions(t *testing.T) {
	tmpdir := t.TempDir()
	t.Setenv("HOME", tmpdir)

	logger, err := NewLogger(&config.Audit{
		AuditFile:  "~/.claude/audit.jsonl",
		AuditLevel: config.AuditAll,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer logger.Close()

	info, err := os.Stat(filepath.Join(tmpdir, ".claude"))
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if info.Mode().Perm() != 0700 {
		t.Errorf("directory permissions = %o, want 0700", info.Mode().Perm())
	}
}

func TestLog(t *testing.T) {
	tmpdir := t.TempDir()
	logFile := filepath.Join(tmpdir, "audit.jsonl")

	logger, err := NewLogger(&config.Audit{
		AuditFile:  logFile,
		AuditLevel: config.AuditAll,
	})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer logger.Close()

	tests := []struct {
		name         string
		input        *hook.Input
		result       engine.Result
		matched      bool
		wantWritten  bool
		wantDecision string
	}{
		{
			name: "all level writes unmatched",
			input: &hook.Input{
				ToolName:  "Bash",
				ToolInput: hook.ToolInput{Command: "ls"},
			},
			result:       engine.Result{},
			matched:      false,
			wantWritten:  true,
			wantDecision: "passthrough",
		},
		{
			name: "all level writes matched",
			input: &hook.Input{
				ToolName:  "Bash",
				ToolInput: hook.ToolInput{Command: "rm -rf /"},
			},
			result: engine.Result{
				Decision: "deny",
				Rule:     &config.Rule{Type: config.RuleDeny, Tool: "Bash", Reason: "blocked"},
			},
			matched:      true,
			wantWritten:  true,
			wantDecision: "deny",
		},
		{
			name: "passthrough when decision empty",
			input: &hook.Input{
				ToolName:  "Read",
				ToolInput: hook.ToolInput{FilePath: "/tmp/foo"},
			},
			result:       engine.Result{Decision: ""},
			matched:      false,
			wantWritten:  true,
			wantDecision: "passthrough",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Truncate before each subtest
			if err := os.Truncate(logFile, 0); err != nil {
				t.Fatalf("truncate: %v", err)
			}

			if err := logger.Log(tt.input, tt.result, tt.matched); err != nil {
				t.Fatalf("Log: %v", err)
			}

			data, err := os.ReadFile(logFile)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}

			if !tt.wantWritten {
				if len(data) > 0 {
					t.Fatalf("expected no output, got %s", data)
				}
				return
			}

			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) != 1 {
				t.Fatalf("expected 1 line, got %d", len(lines))
			}

			var entry Entry
			if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			if entry.Decision != tt.wantDecision {
				t.Errorf("decision = %q, want %q", entry.Decision, tt.wantDecision)
			}
			if entry.ToolName != tt.input.ToolName {
				t.Errorf("tool_name = %q, want %q", entry.ToolName, tt.input.ToolName)
			}
		})
	}
}

func TestLog_matchedLevel_skipsUnmatched(t *testing.T) {
	tmpdir := t.TempDir()
	logFile := filepath.Join(tmpdir, "audit.jsonl")

	logger, err := NewLogger(&config.Audit{
		AuditFile:  logFile,
		AuditLevel: config.AuditMatched,
	})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer logger.Close()

	err = logger.Log(&hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "ls"},
	}, engine.Result{}, false)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) > 0 {
		t.Fatalf("expected no output for unmatched at matched level, got %s", data)
	}
}

func TestLog_nilLogger(t *testing.T) {
	var logger *Logger
	err := logger.Log(&hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "ls"},
	}, engine.Result{}, false)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestLogCombined(t *testing.T) {
	logRule := &config.Rule{Type: config.RuleLog, Tool: "Bash", Reason: "Audit"}

	tests := []struct {
		name               string
		result             engine.Result
		logResults         []engine.Result
		wantDecision       string
		wantRuleReason     string
		wantRuleToolRegex  string
		wantLogReasons     []string
	}{
		{
			name:           "passthrough with log rule",
			result:         engine.Result{},
			logResults:     []engine.Result{{Rule: logRule, Reason: "Audit"}},
			wantDecision:   "passthrough",
			wantRuleReason: "no rule matched",
			wantLogReasons: []string{"Audit"},
		},
		{
			name: "deny with log rule",
			result: engine.Result{
				Decision: "deny",
				Rule:     &config.Rule{Type: config.RuleDeny, Tool: "Bash", Reason: "Blocked rm -rf"},
				Reason:   "Blocked rm -rf",
			},
			logResults:     []engine.Result{{Rule: logRule, Reason: "Audit"}},
			wantDecision:   "deny",
			wantRuleReason: "Blocked rm -rf",
			wantLogReasons: []string{"Audit"},
		},
		{
			name:           "passthrough no log rules",
			result:         engine.Result{},
			logResults:     nil,
			wantDecision:   "passthrough",
			wantRuleReason: "no rule matched",
			wantLogReasons: nil,
		},
		{
			name: "allow with no log rules",
			result: engine.Result{
				Decision: "allow",
				Rule:     &config.Rule{Type: config.RuleAllow, Tool: "Bash", Reason: "Simple command"},
				Reason:   "Simple command",
			},
			logResults:     nil,
			wantDecision:   "allow",
			wantRuleReason: "Simple command",
			wantLogReasons: nil,
		},
		{
			name: "tool_regex rule populates rule_tool_regex",
			result: engine.Result{
				Decision: "allow",
				Rule:     &config.Rule{Type: config.RuleAllow, ToolRegex: "^mcp__workshop__", Reason: "MCP tools"},
				Reason:   "MCP tools",
			},
			logResults:        nil,
			wantDecision:      "allow",
			wantRuleReason:    "MCP tools",
			wantRuleToolRegex: "^mcp__workshop__",
			wantLogReasons:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpdir := t.TempDir()
			logFile := filepath.Join(tmpdir, "audit.jsonl")

			logger, err := NewLogger(&config.Audit{
				AuditFile:  logFile,
				AuditLevel: config.AuditAll,
			})
			if err != nil {
				t.Fatalf("NewLogger: %v", err)
			}
			defer logger.Close()

			input := &hook.Input{
				ToolName:  "Bash",
				ToolInput: hook.ToolInput{Command: "ls"},
			}

			if err := logger.LogCombined(input, tt.result, tt.logResults); err != nil {
				t.Fatalf("LogCombined: %v", err)
			}

			data, err := os.ReadFile(logFile)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}

			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) != 1 {
				t.Fatalf("expected exactly 1 line, got %d: %q", len(lines), data)
			}

			var entry Entry
			if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			if entry.Decision != tt.wantDecision {
				t.Errorf("decision = %q, want %q", entry.Decision, tt.wantDecision)
			}
			if entry.RuleReason != tt.wantRuleReason {
				t.Errorf("rule_reason = %q, want %q", entry.RuleReason, tt.wantRuleReason)
			}
			if entry.RuleToolRegex != tt.wantRuleToolRegex {
				t.Errorf("rule_tool_regex = %q, want %q", entry.RuleToolRegex, tt.wantRuleToolRegex)
			}
			if len(entry.LogReasons) != len(tt.wantLogReasons) {
				t.Errorf("log_reasons = %v, want %v", entry.LogReasons, tt.wantLogReasons)
			} else {
				for i, r := range tt.wantLogReasons {
					if entry.LogReasons[i] != r {
						t.Errorf("log_reasons[%d] = %q, want %q", i, entry.LogReasons[i], r)
					}
				}
			}
		})
	}
}

func TestLogCombined_matchedLevel_writesPassthroughWithLogRules(t *testing.T) {
	tmpdir := t.TempDir()
	logFile := filepath.Join(tmpdir, "audit.jsonl")

	logger, err := NewLogger(&config.Audit{
		AuditFile:  logFile,
		AuditLevel: config.AuditMatched,
	})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer logger.Close()

	logRule := &config.Rule{Type: config.RuleLog, Tool: "Bash", Reason: "Audit"}
	err = logger.LogCombined(&hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "ls"},
	}, engine.Result{}, []engine.Result{{Rule: logRule, Reason: "Audit"}})
	if err != nil {
		t.Fatalf("LogCombined: %v", err)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line (log rule matched), got %d", len(lines))
	}
}

func TestLogCombined_exactlyOneLinePerInvocation(t *testing.T) {
	tmpdir := t.TempDir()
	logFile := filepath.Join(tmpdir, "audit.jsonl")

	logger, err := NewLogger(&config.Audit{
		AuditFile:  logFile,
		AuditLevel: config.AuditAll,
	})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer logger.Close()

	logRule := &config.Rule{Type: config.RuleLog, Tool: "Bash", Reason: "Audit"}
	inputs := []*hook.Input{
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "ls"}},
		{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "git status"}},
		{ToolName: "Read", ToolInput: hook.ToolInput{FilePath: "/tmp/foo"}},
	}
	results := []engine.Result{
		{},
		{Decision: "allow", Rule: &config.Rule{Type: config.RuleAllow, Tool: "Bash", Reason: "Dev tool"}},
		{},
	}
	logResultSets := [][]engine.Result{
		{{Rule: logRule, Reason: "Audit"}},
		{{Rule: logRule, Reason: "Audit"}},
		nil,
	}

	for i := range inputs {
		if err := logger.LogCombined(inputs[i], results[i], logResultSets[i]); err != nil {
			t.Fatalf("LogCombined[%d]: %v", i, err)
		}
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != len(inputs) {
		t.Fatalf("expected %d lines (one per invocation), got %d:\n%s", len(inputs), len(lines), data)
	}
	for i, line := range lines {
		var entry Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("line %d unmarshal: %v", i, err)
		}
		if entry.ToolName != inputs[i].ToolName {
			t.Errorf("line %d: tool_name = %q, want %q", i, entry.ToolName, inputs[i].ToolName)
		}
	}
}

func TestLogCombined_matchedLevel_skipsPassthroughWithNoLogRules(t *testing.T) {
	tmpdir := t.TempDir()
	logFile := filepath.Join(tmpdir, "audit.jsonl")

	logger, err := NewLogger(&config.Audit{
		AuditFile:  logFile,
		AuditLevel: config.AuditMatched,
	})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer logger.Close()

	err = logger.LogCombined(&hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "ls"},
	}, engine.Result{}, nil)
	if err != nil {
		t.Fatalf("LogCombined: %v", err)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) > 0 {
		t.Fatalf("expected no output for passthrough at matched level, got %s", data)
	}
}

func TestLogCombined_nilLogger(t *testing.T) {
	var logger *Logger
	err := logger.LogCombined(&hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "ls"},
	}, engine.Result{}, nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestSummarizeInput(t *testing.T) {
	tests := []struct {
		name  string
		input *hook.Input
		want  string
	}{
		{
			name:  "Bash",
			input: &hook.Input{ToolName: "Bash", ToolInput: hook.ToolInput{Command: "ls -la"}},
			want:  "ls -la",
		},
		{
			name:  "Read",
			input: &hook.Input{ToolName: "Read", ToolInput: hook.ToolInput{FilePath: "/tmp/foo"}},
			want:  "/tmp/foo",
		},
		{
			name:  "Edit",
			input: &hook.Input{ToolName: "Edit", ToolInput: hook.ToolInput{FilePath: "/tmp/bar"}},
			want:  "/tmp/bar",
		},
		{
			name:  "Write",
			input: &hook.Input{ToolName: "Write", ToolInput: hook.ToolInput{FilePath: "/tmp/baz"}},
			want:  "/tmp/baz",
		},
		{
			name:  "Update",
			input: &hook.Input{ToolName: "Update", ToolInput: hook.ToolInput{FilePath: "/tmp/upd"}},
			want:  "/tmp/upd",
		},
		{
			name:  "Glob",
			input: &hook.Input{ToolName: "Glob", ToolInput: hook.ToolInput{Path: "/tmp/**"}},
			want:  "/tmp/**",
		},
		{
			name:  "Grep",
			input: &hook.Input{ToolName: "Grep", ToolInput: hook.ToolInput{Path: "/tmp"}},
			want:  "/tmp",
		},
		{
			name:  "unknown tool",
			input: &hook.Input{ToolName: "mcp__something__tool", ToolInput: hook.ToolInput{}},
			want:  "mcp__something__tool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := summarizeInput(tt.input)
			if got != tt.want {
				t.Errorf("summarizeInput() = %q, want %q", got, tt.want)
			}
		})
	}
}
