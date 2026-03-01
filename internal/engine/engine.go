// Package engine implements the rule matching logic.
package engine

import (
	"github.com/dokipen/claude-approve/internal/config"
	"github.com/dokipen/claude-approve/internal/hook"
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
// Rules are evaluated in order: deny rules first, then allow, then ask.
// Log rules are collected separately and don't affect the permission decision.
// If no deny/allow/ask rule matches, the result is passthrough.
func Evaluate(cfg *config.Config, input *hook.Input) (Result, []Result) {
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

	case "Read", "Edit", "Write":
		if rule.CompiledFilePath() != nil {
			return rule.CompiledFilePath().MatchString(input.ToolInput.FilePath)
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

	case "Read", "Edit", "Write":
		if rule.CompiledFilePathExclude() != nil {
			return rule.CompiledFilePathExclude().MatchString(input.ToolInput.FilePath)
		}
	}
	return false
}
