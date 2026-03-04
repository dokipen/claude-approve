package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/dokipen/claude-approve/internal/hook"
)

// buildBinary builds the claude-approve binary and returns its path.
func buildBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "claude-approve")
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Dir = filepath.Dir(mustFindMainGo(t))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, out)
	}
	return binary
}

func mustFindMainGo(t *testing.T) string {
	t.Helper()
	// main.go is in the same directory as this test file
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot get working directory: %v", err)
	}
	return filepath.Join(wd, "main.go")
}

func TestRunWithInvalidConfig_OutputsAskDecision(t *testing.T) {
	binary := buildBinary(t)

	// Create an invalid config file
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "bad.toml")
	os.WriteFile(configPath, []byte(`
[audit]
audit_level = "bogus"
`), 0644)

	// Provide valid stdin (the hook input)
	stdinData, _ := json.Marshal(hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "ls"},
	})

	cmd := exec.Command(binary, "run", "--config", configPath)
	cmd.Stdin = bytes.NewReader(stdinData)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v (stderr: %s)", err, tryStderr(cmd))
	}

	var output hook.Output
	if err := json.Unmarshal(out, &output); err != nil {
		t.Fatalf("failed to parse output JSON: %v\nraw: %s", err, out)
	}

	if output.HookSpecificOutput == nil {
		t.Fatal("expected hookSpecificOutput, got nil")
	}
	if output.HookSpecificOutput.PermissionDecision != "ask" {
		t.Errorf("decision = %q, want %q", output.HookSpecificOutput.PermissionDecision, "ask")
	}
	if output.HookSpecificOutput.PermissionDecisionReason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestRunWithMissingConfig_OutputsAskDecision(t *testing.T) {
	binary := buildBinary(t)

	stdinData, _ := json.Marshal(hook.Input{
		ToolName:  "Bash",
		ToolInput: hook.ToolInput{Command: "ls"},
	})

	cmd := exec.Command(binary, "run", "--config", "/nonexistent/path.toml")
	cmd.Stdin = bytes.NewReader(stdinData)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}

	var output hook.Output
	if err := json.Unmarshal(out, &output); err != nil {
		t.Fatalf("failed to parse output JSON: %v\nraw: %s", err, out)
	}

	if output.HookSpecificOutput == nil {
		t.Fatal("expected hookSpecificOutput, got nil")
	}
	if output.HookSpecificOutput.PermissionDecision != "ask" {
		t.Errorf("decision = %q, want %q", output.HookSpecificOutput.PermissionDecision, "ask")
	}
}

func TestValidateWithInvalidConfig_StillExitsNonZero(t *testing.T) {
	binary := buildBinary(t)

	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "bad.toml")
	os.WriteFile(configPath, []byte(`
[audit]
audit_level = "bogus"
`), 0644)

	cmd := exec.Command(binary, "validate", "--config", configPath)
	err := cmd.Run()
	if err == nil {
		t.Error("expected validate to exit non-zero for invalid config")
	}
}

// tryStderr attempts to capture stderr from a failed command.
func tryStderr(cmd *exec.Cmd) string {
	if cmd.Stderr != nil {
		if buf, ok := cmd.Stderr.(*bytes.Buffer); ok {
			return buf.String()
		}
	}
	return "(stderr not captured)"
}
