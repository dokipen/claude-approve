// Package shellsplit extracts individual commands from compound shell expressions.
package shellsplit

import (
	"bytes"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Split parses a shell command string and extracts all individual commands,
// including those inside control structures (if/for/while), pipelines,
// logical operators (&&, ||), and command substitutions ($(...), `...`).
//
// It uses a full POSIX/Bash shell parser, so it correctly handles quoting,
// escaping, here-docs, and nested constructs.
//
// If parsing fails (e.g. unbalanced quotes), the whole command is returned
// as a single element — which is the safe fallback (no splitting means the
// engine evaluates the original string as-is).
func Split(cmd string) []string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return nil
	}

	parser := syntax.NewParser(syntax.KeepComments(false))
	file, err := parser.Parse(strings.NewReader(cmd), "")
	if err != nil {
		// Parse failed — return whole command as-is (safe fallback).
		return []string{cmd}
	}

	printer := syntax.NewPrinter()
	var commands []string

	syntax.Walk(file, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}

		// Collect leaf commands (simple commands, declarations, test expressions).
		// Skip compound nodes (BinaryCmd, IfClause, etc.) — Walk descends
		// into them to find the leaf commands inside.
		switch cmd := stmt.Cmd.(type) {
		case *syntax.CallExpr:
			// Skip pure variable assignments (e.g. "FOO=$(cmd)").
			// The inner command substitution is already extracted by
			// the walk, so emitting the assignment wrapper would create
			// a phantom sub-command that matches no rules and causes
			// passthrough to override real decisions in compound eval.
			if len(cmd.Args) == 0 && len(cmd.Assigns) > 0 {
				break
			}
			var buf bytes.Buffer
			printer.Print(&buf, stmt)
			s := strings.TrimSpace(buf.String())
			if s != "" {
				commands = append(commands, s)
			}
		case *syntax.DeclClause, *syntax.TestClause:
			var buf bytes.Buffer
			printer.Print(&buf, stmt)
			s := strings.TrimSpace(buf.String())
			if s != "" {
				commands = append(commands, s)
			}
		}

		return true // always continue walking to find nested commands
	})

	if len(commands) == 0 {
		return []string{cmd}
	}
	return commands
}
