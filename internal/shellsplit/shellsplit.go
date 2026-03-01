// Package shellsplit splits compound shell commands into individual sub-commands.
package shellsplit

import "strings"

// Split breaks a shell command string into individual sub-commands by splitting
// on unquoted compound operators: &&, ||, ;, |, &
//
// It respects single quotes, double quotes, backslash escapes, and does not
// split inside $(...) subshells or backtick expressions.
func Split(cmd string) []string {
	var commands []string
	var current strings.Builder

	inSingleQuote := false
	inDoubleQuote := false
	inBacktick := false
	parenDepth := 0 // tracks $(...) nesting

	i := 0
	for i < len(cmd) {
		ch := cmd[i]

		// Backslash escapes (not inside single quotes)
		if ch == '\\' && !inSingleQuote && i+1 < len(cmd) {
			current.WriteByte(ch)
			current.WriteByte(cmd[i+1])
			i += 2
			continue
		}

		// Quote tracking
		if ch == '\'' && !inDoubleQuote && !inBacktick {
			inSingleQuote = !inSingleQuote
			current.WriteByte(ch)
			i++
			continue
		}
		if ch == '"' && !inSingleQuote && !inBacktick {
			inDoubleQuote = !inDoubleQuote
			current.WriteByte(ch)
			i++
			continue
		}
		if ch == '`' && !inSingleQuote {
			inBacktick = !inBacktick
			current.WriteByte(ch)
			i++
			continue
		}

		// $(...) subshell tracking (not inside quotes)
		if ch == '$' && !inSingleQuote && !inDoubleQuote && !inBacktick &&
			i+1 < len(cmd) && cmd[i+1] == '(' {
			parenDepth++
			current.WriteByte(ch)
			current.WriteByte(cmd[i+1])
			i += 2
			continue
		}
		if ch == ')' && !inSingleQuote && !inDoubleQuote && !inBacktick && parenDepth > 0 {
			parenDepth--
			current.WriteByte(ch)
			i++
			continue
		}

		// Only split when outside all quoting contexts
		if !inSingleQuote && !inDoubleQuote && !inBacktick && parenDepth == 0 {
			// Two-character operators: &&, ||
			if i+1 < len(cmd) {
				pair := cmd[i : i+2]
				if pair == "&&" || pair == "||" {
					flush(&commands, &current)
					i += 2
					continue
				}
			}

			// Single-character operators: ;, |, &
		// For &, skip if preceded by > (redirect like 2>&1)
			if ch == ';' || ch == '|' {
				flush(&commands, &current)
				i++
				continue
			}
			if ch == '&' {
				s := current.String()
				if len(s) > 0 && s[len(s)-1] == '>' {
					// Part of a redirect (e.g. >&, 2>&1), not a separator
					current.WriteByte(ch)
					i++
					continue
				}
				flush(&commands, &current)
				i++
				continue
			}
		}

		current.WriteByte(ch)
		i++
	}

	flush(&commands, &current)
	return commands
}

func flush(commands *[]string, current *strings.Builder) {
	s := strings.TrimSpace(current.String())
	if s != "" {
		*commands = append(*commands, s)
	}
	current.Reset()
}
