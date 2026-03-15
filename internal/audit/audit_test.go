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
		file      string // relative to tmpdir unless prefixed with ~/
		wantNil   bool
		wantErr   bool
		setupHome bool // if true, set HOME to tmpdir for ~ expansion
	}{
		{
			name:    "off returns nil",
			level:   config.AuditOff,
			file:    "audit.jsonl",
			wantNil: true,
		},
		{
			name:    "empty file returns nil",
			level:   config.AuditAll,
			file:    "",
			wantNil: true,
		},
		{
			name:  "absolute path creates file",
			level: config.AuditAll,
			file:  "", // filled in by test
		},
		{
			name:      "tilde expansion creates file",
			level:     config.AuditAll,
			file:      "~/.claude/audit.jsonl",
			setupHome: true,
		},
		{
			name:      "tilde expansion with nested dirs",
			level:     config.AuditAll,
			file:      "~/.claude/logs/deep/audit.jsonl",
			setupHome: true,
		},
		{
			name:  "creates parent directories",
			level: config.AuditAll,
			file:  "", // filled in by test
		},
		{
			name:  "existing directory works",
			level: config.AuditMatched,
			file:  "", // filled in by test
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpdir := t.TempDir()

			auditFile := tt.file
			switch tt.name {
			case "absolute path creates file":
				auditFile = filepath.Join(tmpdir, "audit.jsonl")
			case "creates parent directories":
				auditFile = filepath.Join(tmpdir, "sub", "dir", "audit.jsonl")
			case "existing directory works":
				auditFile = filepath.Join(tmpdir, "audit.jsonl")
			}

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

func TestNewLogger_tildeNotExpanded_withoutSlash(t *testing.T) {
	// A bare "~" or "~otheruser/path" should NOT be expanded
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

	_, err := NewLogger(&config.Audit{
		AuditFile:  "~/.claude/audit.jsonl",
		AuditLevel: config.AuditAll,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
		level        config.AuditLevel
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

func TestSummarizeInput(t *testing.T) {
	tests := []struct {
		name string
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
			name:  "unknown tool",
			input: &hook.Input{ToolName: "Glob", ToolInput: hook.ToolInput{}},
			want:  "",
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
