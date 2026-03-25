package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildBinary builds the claude-approve binary and returns its path.
func buildBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "claude-approve")
	cmd := exec.Command("go", "build", "-o", binary, ".")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot get working directory: %v", err)
	}
	cmd.Dir = wd
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, out)
	}
	return binary
}

func TestRunWithInvalidConfig_Passthrough(t *testing.T) {
	binary := buildBinary(t)

	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "bad.toml")
	if err := os.WriteFile(configPath, []byte(`
[audit]
audit_level = "bogus"
`), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	var stderr bytes.Buffer
	cmd := exec.Command(binary, "run", "--config", configPath)
	cmd.Stdin = strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"ls"}}`)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v\nstderr: %s", err, stderr.String())
	}

	// Passthrough means no stdout output
	if len(bytes.TrimSpace(out)) > 0 {
		t.Errorf("expected no stdout (passthrough), got: %s", out)
	}

	// Config error should be logged to stderr
	if !strings.Contains(stderr.String(), "config error") {
		t.Errorf("expected config error on stderr, got: %s", stderr.String())
	}
}

func TestRunWithMissingConfig_Passthrough(t *testing.T) {
	binary := buildBinary(t)

	var stderr bytes.Buffer
	cmd := exec.Command(binary, "run", "--config", "/nonexistent/path.toml")
	cmd.Stdin = strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"ls"}}`)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v\nstderr: %s", err, stderr.String())
	}

	if len(bytes.TrimSpace(out)) > 0 {
		t.Errorf("expected no stdout (passthrough), got: %s", out)
	}

	if !strings.Contains(stderr.String(), "config error") {
		t.Errorf("expected config error on stderr, got: %s", stderr.String())
	}
}

func TestValidateWithInvalidConfig_StillExitsNonZero(t *testing.T) {
	binary := buildBinary(t)

	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "bad.toml")
	if err := os.WriteFile(configPath, []byte(`
[audit]
audit_level = "bogus"
`), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cmd := exec.Command(binary, "validate", "--config", configPath)
	err := cmd.Run()
	if err == nil {
		t.Error("expected validate to exit non-zero for invalid config")
	}
}

func TestValidateWithUnanchoredRegex(t *testing.T) {
	binary := buildBinary(t)

	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "unanchored.toml")
	if err := os.WriteFile(configPath, []byte(`
[[deny]]
tool = "Write"
file_path_regex = "\\.env$"
reason = "env files"
`), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	var stderr bytes.Buffer
	cmd := exec.Command(binary, "validate", "--config", configPath)
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		t.Errorf("expected validate to exit 0 for config with warnings, got: %v\nstderr: %s", err, stderr.String())
	}

	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "[warning]") {
		t.Errorf("expected stderr to contain '[warning]', got: %s", stderrStr)
	}
}

func TestValidateWithAnchoredRegex(t *testing.T) {
	binary := buildBinary(t)

	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "anchored.toml")
	if err := os.WriteFile(configPath, []byte(`
[[deny]]
tool = "Write"
file_path_regex = "^/home/user/project/"
reason = "project files"
`), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	var stderr bytes.Buffer
	cmd := exec.Command(binary, "validate", "--config", configPath)
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		t.Errorf("expected validate to exit 0 for config with anchored regex, got: %v\nstderr: %s", err, stderr.String())
	}

	stderrStr := stderr.String()
	if strings.Contains(stderrStr, "[warning]") {
		t.Errorf("expected stderr NOT to contain '[warning]' for anchored regex, got: %s", stderrStr)
	}
}
