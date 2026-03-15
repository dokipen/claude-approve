// Package audit handles writing audit log entries.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dokipen/claude-approve/internal/config"
	"github.com/dokipen/claude-approve/internal/engine"
	"github.com/dokipen/claude-approve/internal/hook"
)

// Entry is a single audit log record.
type Entry struct {
	Timestamp  string `json:"timestamp"`
	ToolName   string `json:"tool_name"`
	ToolInput  string `json:"tool_input"`
	RuleType   string `json:"rule_type,omitempty"`
	RuleTool   string `json:"rule_tool,omitempty"`
	RuleReason string `json:"rule_reason,omitempty"`
	Decision   string `json:"decision"`
}

// Logger writes audit entries to a file.
type Logger struct {
	level config.AuditLevel
	file  *os.File
}

// NewLogger creates an audit logger. Returns nil if auditing is off or no file configured.
func NewLogger(cfg *config.Audit) (*Logger, error) {
	if cfg.AuditLevel == config.AuditOff || cfg.AuditFile == "" {
		return nil, nil
	}

	path := cfg.AuditFile
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolving home dir for audit_file: %w", err)
		}
		path = filepath.Join(home, path[2:])
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("creating audit log directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening audit file %s: %w", path, err)
	}

	return &Logger{
		level: cfg.AuditLevel,
		file:  f,
	}, nil
}

// Close closes the audit log file.
func (l *Logger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}

// Log writes an audit entry if appropriate for the audit level.
func (l *Logger) Log(input *hook.Input, result engine.Result, matched bool) error {
	if l == nil {
		return nil
	}

	if l.level == config.AuditMatched && !matched {
		return nil
	}

	inputSummary := summarizeInput(input)
	entry := Entry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		ToolName:  input.ToolName,
		ToolInput: inputSummary,
		Decision:  string(result.Decision),
	}

	if result.Rule != nil {
		entry.RuleType = string(result.Rule.Type)
		entry.RuleTool = result.Rule.Tool
		entry.RuleReason = result.Rule.Reason
	}

	if result.Decision == "" {
		entry.Decision = "passthrough"
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshaling audit entry: %w", err)
	}

	if _, err := fmt.Fprintf(l.file, "%s\n", data); err != nil {
		return fmt.Errorf("writing audit entry: %w", err)
	}
	return nil
}

func summarizeInput(input *hook.Input) string {
	switch input.ToolName {
	case "Bash":
		return input.ToolInput.Command
	case "Read":
		return input.ToolInput.FilePath
	case "Edit":
		return input.ToolInput.FilePath
	case "Write":
		return input.ToolInput.FilePath
	default:
		return ""
	}
}
