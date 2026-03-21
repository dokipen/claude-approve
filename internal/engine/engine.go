// Package engine implements the rule matching logic.
package engine

import (
	"fmt"

	"github.com/dokipen/claude-approve/internal/config"
	"github.com/dokipen/claude-approve/internal/hook"
	"github.com/dokipen/claude-approve/internal/shellsplit"
)

// Decision represents the outcome of rule evaluation.
type Decision string

const (
	DecisionAllow     Decision = "allow"
	DecisionDeny      Decision = "deny"
	DecisionAsk       Decision = "ask"
	DecisionLog       Decision = "log"
	DecisionPassthrough Decision = "" // no rule matched
)

// Result holds the evaluation outcome.
type Result struct {
	Decision Decision
	Reason   string
	Rule     *config.Rule // the rule that matched, nil if passthrough
}

// Evaluate checks the hook input against all rules and returns the first matching decision.
// For Bash commands with compound operators (&&, ||, ;, |), each sub-command is evaluated
// independently and the most restrictive decision wins.
// Rules are evaluated in order: deny rules first, then allow, then ask.
// Log rules are collected separately and don't affect the permission decision.
// If no deny/allow/ask rule matches, the result is passthrough.
func Evaluate(cfg *config.Config, input *hook.Input) (Result, []Result) {
	if input.ToolName == "Bash" && input.ToolInput.Command != "" {
		parts := shellsplit.Split(input.ToolInput.Command)
		if len(parts) > 1 {
			return evaluateCompound(cfg, input, parts)
		}
		// If split extracted a different command (e.g. bash -c 'cmd' → cmd),
		// evaluate the extracted command instead of the original.
		if len(parts) == 1 && parts[0] != input.ToolInput.Command {
			modified := *input
			modified.ToolInput.Command = parts[0]
			return evaluateSingle(cfg, &modified)
		}
	}
	return evaluateSingle(cfg, input)
}

// evaluateCompound evaluates each sub-command independently and aggregates
// using most-restrictive-wins: deny > ask > passthrough > allow.
func evaluateCompound(cfg *config.Config, original *hook.Input, parts []string) (Result, []Result) {
	var allLogResults []Result
	var aggregated *Result

	for _, part := range parts {
		subInput := &hook.Input{
			SessionID:      original.SessionID,
			TranscriptPath: original.TranscriptPath,
			Cwd:            original.Cwd,
			PermissionMode: original.PermissionMode,
			HookEventName:  original.HookEventName,
			ToolName:       original.ToolName,
			ToolUseID:      original.ToolUseID,
			ToolInput: hook.ToolInput{
				Command:     part,
				Description: original.ToolInput.Description,
			},
		}

		result, logResults := evaluateSingle(cfg, subInput)
		allLogResults = append(allLogResults, logResults...)

		if aggregated == nil || decisionPriority(result.Decision) > decisionPriority(aggregated.Decision) {
			enriched := result
			if enriched.Reason != "" {
				enriched.Reason = fmt.Sprintf("%s [in: %s]", enriched.Reason, part)
			}
			aggregated = &enriched
		}
	}

	if aggregated == nil {
		return Result{Decision: DecisionPassthrough}, allLogResults
	}
	return *aggregated, allLogResults
}

// decisionPriority returns the restrictiveness of a decision (higher = more restrictive).
func decisionPriority(d Decision) int {
	switch d {
	case DecisionDeny:
		return 3
	case DecisionAsk:
		return 2
	case DecisionPassthrough:
		return 1
	case DecisionAllow:
		return 0
	default:
		return 0
	}
}

// evaluateSingle evaluates a single (non-compound) tool call against all rules.
func evaluateSingle(cfg *config.Config, input *hook.Input) (Result, []Result) {
	var logResults []Result
	var permissionResult *Result

	for i := range cfg.Rules {
		rule := &cfg.Rules[i]

		if !matchesTool(rule, input) {
			continue
		}

		if !matchesInput(rule, input) {
			continue
		}

		if isExcluded(rule, input) {
			continue
		}

		switch rule.Type {
		case config.RuleLog:
			logResults = append(logResults, Result{
				Decision: DecisionLog,
				Reason:   rule.Reason,
				Rule:     rule,
			})
		case config.RuleDeny, config.RuleAllow, config.RuleAsk:
			if permissionResult == nil {
				decision := Decision(rule.Type)
				permissionResult = &Result{
					Decision: decision,
					Reason:   rule.Reason,
					Rule:     rule,
				}
			}
		}
	}

	if permissionResult == nil {
		return Result{Decision: DecisionPassthrough}, logResults
	}
	return *permissionResult, logResults
}

// matchesTool checks if the rule applies to this tool.
func matchesTool(rule *config.Rule, input *hook.Input) bool {
	return rule.Tool == input.ToolName
}

// matchesInput checks if the rule's include patterns match the tool input.
func matchesInput(rule *config.Rule, input *hook.Input) bool {
	switch input.ToolName {
	case "Bash":
		if rule.CompiledCommand() != nil {
			return rule.CompiledCommand().MatchString(input.ToolInput.Command)
		}
		// Rule has no command_regex — matches all Bash calls for this tool
		return true

	case "Read", "Edit", "Write", "Update":
		if rule.CompiledFilePath() != nil {
			return rule.CompiledFilePath().MatchString(input.ToolInput.FilePath)
		}
		return true

	// Search is assumed to use "path" like Grep/Glob. If Search uses a different
	// field (e.g. "query"), file_path_regex deny rules will silently not match.
	// Verify against Claude Code hook payload when docs are available.
	case "Grep", "Glob", "Search":
		if rule.CompiledFilePath() != nil {
			return rule.CompiledFilePath().MatchString(input.ToolInput.Path)
		}
		return true

	default:
		return false
	}
}

// isExcluded checks if the rule's exclude patterns disqualify this input.
func isExcluded(rule *config.Rule, input *hook.Input) bool {
	switch input.ToolName {
	case "Bash":
		if rule.CompiledCommandExclude() != nil {
			return rule.CompiledCommandExclude().MatchString(input.ToolInput.Command)
		}

	case "Read", "Edit", "Write", "Update":
		if rule.CompiledFilePathExclude() != nil {
			return rule.CompiledFilePathExclude().MatchString(input.ToolInput.FilePath)
		}

	case "Grep", "Glob", "Search":
		if rule.CompiledFilePathExclude() != nil {
			return rule.CompiledFilePathExclude().MatchString(input.ToolInput.Path)
		}
	}
	return false
}
