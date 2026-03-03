// Package shellsplit extracts individual commands from compound shell expressions.
package shellsplit

import (
	"bytes"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// maxShellRecursionDepth limits recursive extraction of bash -c / sh -c
// inner commands to prevent infinite recursion.
const maxShellRecursionDepth = 10

// shellNames are binary names recognized as shell invocations.
var shellNames = map[string]bool{
	"bash": true, "sh": true,
	"/bin/bash": true, "/bin/sh": true,
	"/usr/bin/bash": true, "/usr/bin/sh": true,
}

// shellAction classifies how a bash/sh invocation should be handled.
type shellAction int

const (
	shellNone    shellAction = iota // not bash/sh
	shellBareCmd                    // bash script.sh (no -c)
	shellDashC                      // bash -c 'cmd'
)

type shellInfo struct {
	action   shellAction
	innerCmd string // set only when action == shellDashC and extractable
}

// Split parses a shell command string and extracts all individual commands,
// including those inside control structures (if/for/while), pipelines,
// logical operators (&&, ||), and command substitutions ($(...), `...`).
//
// bash -c 'cmd' and sh -c 'cmd' invocations are detected and the inner
// command is recursively extracted. Bare bash/sh invocations (without -c)
// are treated as neutral and skipped in compound commands.
//
// It uses a full POSIX/Bash shell parser, so it correctly handles quoting,
// escaping, here-docs, and nested constructs.
//
// If parsing fails (e.g. unbalanced quotes), the whole command is returned
// as a single element — which is the safe fallback (no splitting means the
// engine evaluates the original string as-is).
func Split(cmd string) []string {
	return splitWithDepth(cmd, 0)
}

func splitWithDepth(cmd string, depth int) []string {
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
		switch call := stmt.Cmd.(type) {
		case *syntax.CallExpr:
			// Skip pure variable assignments (e.g. "FOO=$(cmd)").
			// The inner command substitution is already extracted by
			// the walk, so emitting the assignment wrapper would create
			// a phantom sub-command that matches no rules and causes
			// passthrough to override real decisions in compound eval.
			if len(call.Args) == 0 && len(call.Assigns) > 0 {
				break
			}

			// Detect bash/sh invocations and handle specially.
			info := classifyShellCall(call)
			switch info.action {
			case shellDashC:
				if depth < maxShellRecursionDepth && info.innerCmd != "" {
					// Static inner command: recursively extract.
					inner := splitWithDepth(info.innerCmd, depth+1)
					commands = append(commands, inner...)
					return false // don't descend — we handled it
				}
				// Dynamic or empty inner cmd: emit as-is and let
				// walk descend to find CmdSubst nodes inside args.
				var buf bytes.Buffer
				printer.Print(&buf, stmt)
				s := strings.TrimSpace(buf.String())
				if s != "" {
					commands = append(commands, s)
				}
				return true

			case shellBareCmd:
				// Bare bash/sh without -c: emit as normal command
				// so deny rules can still match in compound context.
			}

			// Normal command: emit it.
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

// classifyShellCall determines if a CallExpr is a bash/sh invocation
// and whether it uses -c.
func classifyShellCall(call *syntax.CallExpr) shellInfo {
	if len(call.Args) == 0 {
		return shellInfo{action: shellNone}
	}

	name, ok := wordStaticValue(call.Args[0])
	if !ok || !shellNames[name] {
		return shellInfo{action: shellNone}
	}

	// It's a shell invocation. Find -c flag.
	innerIdx := findDashCArg(call.Args)
	if innerIdx < 0 {
		return shellInfo{action: shellBareCmd}
	}

	innerCmd, ok := wordStaticValue(call.Args[innerIdx])
	if !ok {
		// -c argument contains dynamic content; can't extract.
		return shellInfo{action: shellDashC, innerCmd: ""}
	}
	return shellInfo{action: shellDashC, innerCmd: innerCmd}
}

// findDashCArg scans args (starting after the binary name) for a -c flag.
// Returns the index of the argument after -c (the inner command), or -1.
// Handles standalone -c and combined flags like -xc, -cx, -ec.
// Fails closed: returns -1 if any arg is dynamic or -- is encountered.
func findDashCArg(args []*syntax.Word) int {
	for i := 1; i < len(args); i++ {
		val, ok := wordStaticValue(args[i])
		if !ok {
			// Dynamic arg — cannot determine argument structure.
			return -1
		}

		// -- terminates options; -c after this is a positional arg.
		if val == "--" {
			return -1
		}

		// Standalone -c
		if val == "-c" {
			if i+1 < len(args) {
				return i + 1
			}
			return -1 // -c without argument
		}

		// Combined flags: -xc, -cx, -ec, etc.
		// Single-char flags starting with - (not --); c anywhere in group.
		if len(val) > 2 && val[0] == '-' && val[1] != '-' && strings.ContainsRune(val[1:], 'c') {
			if i+1 < len(args) {
				return i + 1
			}
			return -1
		}
	}
	return -1
}

// wordStaticValue extracts the static string value from a Word.
// Returns (value, true) for Lit, SglQuoted, or DblQuoted words where
// all inner parts are Lit. Returns ("", false) for dynamic content
// (parameter expansions, command substitutions, etc.).
func wordStaticValue(w *syntax.Word) (string, bool) {
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return "", false
				}
				b.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}
