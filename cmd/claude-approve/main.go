package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/dokipen/claude-approve/internal/audit"
	"github.com/dokipen/claude-approve/internal/config"
	"github.com/dokipen/claude-approve/internal/engine"
	"github.com/dokipen/claude-approve/internal/hook"
)

// stdinTimeout is how long we wait for stdin before giving up.
// Claude Code should send input immediately, so 10 seconds is generous.
const stdinTimeout = 10 * time.Second

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: claude-approve <command> [flags]")
		fmt.Fprintln(os.Stderr, "commands: run, validate, test")
		os.Exit(2)
	}

	switch os.Args[1] {
	case "run":
		cmdRun(os.Args[2:])
	case "validate":
		cmdValidate(os.Args[2:])
	case "test":
		cmdTest(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(2)
	}
}

func cmdRun(args []string) {
	configPath := flagConfig(args)
	if configPath == "" {
		fmt.Fprintln(os.Stderr, "error: --config is required")
		os.Exit(2)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "claude-approve config error (passthrough): %v\n", err)
		return
	}

	data, err := readStdinWithTimeout(stdinTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
		os.Exit(2)
	}

	var input hook.Input
	if err := json.Unmarshal(data, &input); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing hook input: %v\n", err)
		os.Exit(2)
	}

	result, logResults := engine.Evaluate(cfg, &input)

	// Set up audit logging
	logger, err := audit.NewLogger(&cfg.Audit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: audit logging failed: %v\n", err)
	}
	defer func() {
		if logger != nil {
			logger.Close()
		}
	}()

	// Log matched log rules
	for _, lr := range logResults {
		if logger != nil {
			logger.Log(&input, lr, true)
		}
	}

	// Log the permission decision
	matched := result.Decision != engine.DecisionPassthrough
	if logger != nil {
		logger.Log(&input, result, matched)
	}

	// Output decision
	switch result.Decision {
	case engine.DecisionAllow, engine.DecisionDeny, engine.DecisionAsk:
		output := hook.Output{
			HookSpecificOutput: &hook.HookSpecificOutput{
				HookEventName:            "PreToolUse",
				PermissionDecision:       string(result.Decision),
				PermissionDecisionReason: result.Reason,
			},
		}
		enc := json.NewEncoder(os.Stdout)
		if err := enc.Encode(output); err != nil {
			fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
			os.Exit(2)
		}

	case engine.DecisionPassthrough:
		// No output = passthrough to normal Claude Code permissions
	}
}

func cmdValidate(args []string) {
	configPath := flagConfig(args)
	if configPath == "" {
		fmt.Fprintln(os.Stderr, "error: --config is required")
		os.Exit(2)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid config: %v\n", err)
		os.Exit(1)
	}

	denyCount, allowCount, askCount, logCount := 0, 0, 0, 0
	for _, r := range cfg.Rules {
		switch r.Type {
		case config.RuleDeny:
			denyCount++
		case config.RuleAllow:
			allowCount++
		case config.RuleAsk:
			askCount++
		case config.RuleLog:
			logCount++
		}
	}

	fmt.Printf("config OK: %d deny, %d allow, %d ask, %d log rules\n",
		denyCount, allowCount, askCount, logCount)
	fmt.Printf("audit: level=%s", cfg.Audit.AuditLevel)
	if cfg.Audit.AuditFile != "" {
		fmt.Printf(", file=%s", cfg.Audit.AuditFile)
	}
	fmt.Println()
}

func cmdTest(args []string) {
	configPath := flagConfig(args)
	if configPath == "" {
		fmt.Fprintln(os.Stderr, "error: --config is required")
		os.Exit(2)
	}

	toolName := flagValue(args, "--tool")
	inputJSON := flagValue(args, "--input")

	if toolName == "" || inputJSON == "" {
		fmt.Fprintln(os.Stderr, "error: --tool and --input are required")
		fmt.Fprintln(os.Stderr, "usage: claude-approve test --config <path> --tool <tool> --input <json>")
		fmt.Fprintln(os.Stderr, "example: claude-approve test --config ~/.claude/hooks-config.toml --tool Bash --input '{\"command\":\"rm -rf /\"}'")
		os.Exit(2)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(2)
	}

	var toolInput hook.ToolInput
	if err := json.Unmarshal([]byte(inputJSON), &toolInput); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing --input JSON: %v\n", err)
		os.Exit(2)
	}

	input := &hook.Input{
		ToolName:  toolName,
		ToolInput: toolInput,
	}

	result, logResults := engine.Evaluate(cfg, input)

	decision := string(result.Decision)
	if decision == "" {
		decision = "passthrough"
	}

	fmt.Printf("tool:     %s\n", toolName)
	fmt.Printf("decision: %s\n", decision)
	if result.Reason != "" {
		fmt.Printf("reason:   %s\n", result.Reason)
	}
	if result.Rule != nil {
		fmt.Printf("matched:  %s rule (tool=%s", result.Rule.Type, result.Rule.Tool)
		if result.Rule.CommandRegex != "" {
			fmt.Printf(", command_regex=%s", result.Rule.CommandRegex)
		}
		if result.Rule.FilePathRegex != "" {
			fmt.Printf(", file_path_regex=%s", result.Rule.FilePathRegex)
		}
		fmt.Println(")")
	}

	if len(logResults) > 0 {
		fmt.Printf("\nlog rules matched: %d\n", len(logResults))
		for _, lr := range logResults {
			fmt.Printf("  - %s\n", lr.Reason)
		}
	}
}

// readStdinWithTimeout reads all of stdin but aborts if it takes too long.
func readStdinWithTimeout(timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		data, err := io.ReadAll(os.Stdin)
		ch <- result{data, err}
	}()

	select {
	case r := <-ch:
		return r.data, r.err
	case <-ctx.Done():
		return nil, fmt.Errorf("timed out after %s waiting for stdin", timeout)
	}
}

// flagConfig extracts --config value from args.
func flagConfig(args []string) string {
	return flagValue(args, "--config")
}

// flagValue extracts a --key value pair from args.
func flagValue(args []string, key string) string {
	for i, arg := range args {
		if arg == key && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(arg, key+"=") {
			return strings.TrimPrefix(arg, key+"=")
		}
	}
	return ""
}
