// Package config handles TOML configuration parsing for claude-approve.
package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// AuditLevel controls what gets logged.
type AuditLevel string

const (
	AuditOff     AuditLevel = "off"
	AuditMatched AuditLevel = "matched"
	AuditAll     AuditLevel = "all"
)

// Audit configures audit logging.
type Audit struct {
	AuditFile  string     `toml:"audit_file"`
	AuditLevel AuditLevel `toml:"audit_level"`
}

// RuleType determines what action a rule takes.
type RuleType string

const (
	RuleDeny  RuleType = "deny"
	RuleAllow RuleType = "allow"
	RuleAsk   RuleType = "ask"
	RuleLog   RuleType = "log"
)

// Rule represents a single permission rule.
type Rule struct {
	Type                 RuleType
	Tool                 string `toml:"tool"`
	ToolRegex            string `toml:"tool_regex"`
	CommandRegex         string `toml:"command_regex"`
	CommandExcludeRegex  string `toml:"command_exclude_regex"`
	FilePathRegex        string `toml:"file_path_regex"`
	FilePathExcludeRegex string `toml:"file_path_exclude_regex"`
	Reason               string `toml:"reason"`

	// Compiled regexes (populated by Compile)
	compiledToolRegex       *regexp.Regexp
	compiledCommand         *regexp.Regexp
	compiledCommandExclude  *regexp.Regexp
	compiledFilePath        *regexp.Regexp
	compiledFilePathExclude *regexp.Regexp
}

// CompiledToolRegex returns the compiled tool regex.
func (r *Rule) CompiledToolRegex() *regexp.Regexp { return r.compiledToolRegex }

// CompiledCommand returns the compiled command regex.
func (r *Rule) CompiledCommand() *regexp.Regexp { return r.compiledCommand }

// CompiledCommandExclude returns the compiled command exclude regex.
func (r *Rule) CompiledCommandExclude() *regexp.Regexp { return r.compiledCommandExclude }

// CompiledFilePath returns the compiled file path regex.
func (r *Rule) CompiledFilePath() *regexp.Regexp { return r.compiledFilePath }

// CompiledFilePathExclude returns the compiled file path exclude regex.
func (r *Rule) CompiledFilePathExclude() *regexp.Regexp { return r.compiledFilePathExclude }

// Compile pre-compiles all regex patterns in the rule.
func (r *Rule) Compile() error {
	if r.Tool != "" && r.ToolRegex != "" {
		return fmt.Errorf("rule has both tool=%q and tool_regex=%q; use one or the other", r.Tool, r.ToolRegex)
	}
	if r.Tool == "" && r.ToolRegex == "" {
		return fmt.Errorf("rule must have either tool or tool_regex")
	}

	if r.ToolRegex != "" && (r.CommandRegex != "" || r.CommandExcludeRegex != "" || r.FilePathRegex != "" || r.FilePathExcludeRegex != "") {
		return fmt.Errorf("tool_regex rules cannot have input constraints (command_regex, command_exclude_regex, file_path_regex, file_path_exclude_regex); use tool= for structured tool types")
	}

	var err error
	if r.ToolRegex != "" {
		r.compiledToolRegex, err = regexp.Compile(r.ToolRegex)
		if err != nil {
			return fmt.Errorf("invalid tool_regex %q: %w", r.ToolRegex, err)
		}
	}
	if r.CommandRegex != "" {
		r.compiledCommand, err = regexp.Compile(r.CommandRegex)
		if err != nil {
			return fmt.Errorf("invalid command_regex %q: %w", r.CommandRegex, err)
		}
	}
	if r.CommandExcludeRegex != "" {
		r.compiledCommandExclude, err = regexp.Compile(r.CommandExcludeRegex)
		if err != nil {
			return fmt.Errorf("invalid command_exclude_regex %q: %w", r.CommandExcludeRegex, err)
		}
	}
	if r.FilePathRegex != "" {
		r.compiledFilePath, err = regexp.Compile(r.FilePathRegex)
		if err != nil {
			return fmt.Errorf("invalid file_path_regex %q: %w", r.FilePathRegex, err)
		}
	}
	if r.FilePathExcludeRegex != "" {
		r.compiledFilePathExclude, err = regexp.Compile(r.FilePathExcludeRegex)
		if err != nil {
			return fmt.Errorf("invalid file_path_exclude_regex %q: %w", r.FilePathExcludeRegex, err)
		}
	}
	return nil
}

// rawConfig is the raw TOML structure before processing.
type rawConfig struct {
	Audit Audit  `toml:"audit"`
	Deny  []Rule `toml:"deny"`
	Allow []Rule `toml:"allow"`
	Ask   []Rule `toml:"ask"`
	Log   []Rule `toml:"log"`
}

// Config is the fully parsed and compiled configuration.
type Config struct {
	Audit Audit
	Rules []Rule // All rules, ordered: deny, ask, allow, log
}

// Load reads and parses a TOML config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	return Parse(string(data))
}

// Parse parses TOML config from a string.
func Parse(data string) (*Config, error) {
	var raw rawConfig
	if _, err := toml.Decode(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing TOML: %w", err)
	}

	if raw.Audit.AuditLevel == "" {
		raw.Audit.AuditLevel = AuditMatched
	}

	switch raw.Audit.AuditLevel {
	case AuditOff, AuditMatched, AuditAll:
	default:
		return nil, fmt.Errorf("invalid audit_level: %q (must be off, matched, or all)", raw.Audit.AuditLevel)
	}

	cfg := &Config{
		Audit: raw.Audit,
	}

	// Tag and collect rules in evaluation order: deny > ask > allow > log
	for i := range raw.Deny {
		raw.Deny[i].Type = RuleDeny
		cfg.Rules = append(cfg.Rules, raw.Deny[i])
	}
	for i := range raw.Ask {
		raw.Ask[i].Type = RuleAsk
		cfg.Rules = append(cfg.Rules, raw.Ask[i])
	}
	for i := range raw.Allow {
		raw.Allow[i].Type = RuleAllow
		cfg.Rules = append(cfg.Rules, raw.Allow[i])
	}
	for i := range raw.Log {
		raw.Log[i].Type = RuleLog
		cfg.Rules = append(cfg.Rules, raw.Log[i])
	}

	// Compile all regexes
	for i := range cfg.Rules {
		if err := cfg.Rules[i].Compile(); err != nil {
			return nil, fmt.Errorf("rule %d (%s/%s): %w", i, cfg.Rules[i].Type, cfg.Rules[i].Tool, err)
		}
	}

	return cfg, nil
}

// Validate checks the config for errors without returning the config.
func Validate(path string) error {
	_, err := Load(path)
	return err
}

// Warning represents a non-fatal configuration issue.
type Warning struct {
	Message string
}

// hasUnanchoredAlternation reports whether a pattern that starts with "^" has
// any alternation branch that does not start with "^". This is best-effort
// only: it splits naively on "|" without full regex parsing. Known false
// positives (safe patterns that trigger a spurious warning):
//   - grouped alternation: "^(foo|bar)" — the "|" inside the group splits incorrectly
//   - escaped pipes: "^foo\|bar" — backslash escapes are not respected
//   - pipes inside character classes: "^foo[a|b]" — the "|" inside [...] splits incorrectly
func hasUnanchoredAlternation(pattern string) bool {
	if !strings.HasPrefix(pattern, "^") {
		return false
	}
	branches := strings.Split(pattern, "|")
	for _, branch := range branches[1:] {
		if !strings.HasPrefix(branch, "^") {
			return true
		}
	}
	return false
}

// Warnings returns a list of non-fatal configuration warnings for cfg.
// Currently warns about file_path_regex and file_path_exclude_regex patterns
// that are not anchored at the start, which allows substring matching and can
// lead to traversal bypasses.
//
// This is a best-effort heuristic: it checks whether the pattern string starts
// with "^", and also detects alternation branches that lack a "^" anchor.
// It won't catch all cases — for example, alternations inside groups like
// "(^foo|bar)" are not detected. Use anchored patterns throughout to avoid
// false confidence.
func Warnings(cfg *Config) []Warning {
	var warnings []Warning
	for _, r := range cfg.Rules {
		if r.FilePathRegex != "" && !strings.HasPrefix(r.FilePathRegex, "^") {
			warnings = append(warnings, Warning{
				Message: fmt.Sprintf(
					"rule %q: file_path_regex %q is not anchored at the start (no ^); paths are matched as substrings, which may allow traversal bypass",
					r.Reason, r.FilePathRegex,
				),
			})
		} else if r.FilePathRegex != "" && hasUnanchoredAlternation(r.FilePathRegex) {
			warnings = append(warnings, Warning{
				Message: fmt.Sprintf(
					"rule %q: file_path_regex %q has an alternation branch without a ^ anchor; unanchored branches are matched as substrings, which may allow traversal bypass",
					r.Reason, r.FilePathRegex,
				),
			})
		}
		if r.FilePathExcludeRegex != "" && !strings.HasPrefix(r.FilePathExcludeRegex, "^") {
			warnings = append(warnings, Warning{
				Message: fmt.Sprintf(
					"rule %q: file_path_exclude_regex %q is not anchored at the start (no ^); paths are matched as substrings, which may allow traversal bypass",
					r.Reason, r.FilePathExcludeRegex,
				),
			})
		} else if r.FilePathExcludeRegex != "" && hasUnanchoredAlternation(r.FilePathExcludeRegex) {
			warnings = append(warnings, Warning{
				Message: fmt.Sprintf(
					"rule %q: file_path_exclude_regex %q has an alternation branch without a ^ anchor; unanchored branches are matched as substrings, which may allow traversal bypass",
					r.Reason, r.FilePathExcludeRegex,
				),
			})
		}
	}
	return warnings
}
