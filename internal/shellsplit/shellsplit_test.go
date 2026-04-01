package shellsplit

import (
	"testing"
)

func TestSplit(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "single command",
			input: "git status",
			want:  []string{"git status"},
		},
		{
			name:  "and operator",
			input: "git status && rm -rf /",
			want:  []string{"git status", "rm -rf /"},
		},
		{
			name:  "or operator",
			input: "ls || echo fail",
			want:  []string{"ls", "echo fail"},
		},
		{
			name:  "semicolon",
			input: "ls; pwd",
			want:  []string{"ls", "pwd"},
		},
		{
			name:  "pipe",
			input: "cat file | grep foo",
			want:  []string{"cat file", "grep foo"},
		},
		{
			name:  "background ampersand",
			input: "sleep 5 &",
			want:  []string{"sleep 5 &"},
		},
		{
			name:  "single quoted operators",
			input: "echo 'a && b'",
			want:  []string{"echo 'a && b'"},
		},
		{
			name:  "double quoted operators",
			input: `echo "a && b"`,
			want:  []string{`echo "a && b"`},
		},
		{
			name:  "mixed operators",
			input: "a && b || c; d | e",
			want:  []string{"a", "b", "c", "d", "e"},
		},
		{
			name:  "triple chain",
			input: "a && b && c",
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "whitespace only",
			input: "   ",
			want:  nil,
		},
		{
			name:  "subshell commands extracted",
			input: "echo $(git status && git log)",
			want:  []string{"echo $(git status && git log)", "git status", "git log"},
		},
		{
			name:  "nested subshell commands extracted",
			input: "echo $(a && $(b || c))",
			want:  []string{"echo $(a && $(b || c))", "a", "$(b || c)", "b", "c"},
		},
		{
			name:  "subshell then operator",
			input: "echo $(cat file) && rm -rf /",
			want:  []string{"echo $(cat file)", "cat file", "rm -rf /"},
		},
		{
			name:  "backtick commands extracted (printer normalizes to $())",
			input: "echo `git status && git log`",
			want:  []string{"echo $(git status && git log)", "git status", "git log"},
		},
		{
			name:  "trailing semicolon",
			input: "ls;",
			want:  []string{"ls"},
		},
		{
			name:  "leading whitespace",
			input: "  git status && git log  ",
			want:  []string{"git status", "git log"},
		},
		{
			name:  "unbalanced quote fallback",
			input: "echo 'hello && rm -rf /",
			want:  []string{"echo 'hello && rm -rf /"},
		},
		{
			name:  "pipe with redirect",
			input: "cmd 2>&1 | grep error",
			want:  []string{"cmd 2>&1", "grep error"},
		},
		// Control structures — the key improvement over the custom tokenizer
		{
			name:  "if then fi",
			input: "if git status; then echo ok; fi",
			want:  []string{"git status", "echo ok"},
		},
		{
			name:  "if then else fi",
			input: "if [ -f foo ]; then echo yes; else echo no; fi",
			want:  []string{"echo yes", "echo no"},
		},
		{
			name:  "for loop",
			input: "for f in *.txt; do cat \"$f\"; done",
			want:  []string{"cat \"$f\""},
		},
		{
			name:  "while loop",
			input: "while read line; do echo \"$line\"; done < file.txt",
			want:  []string{"read line", "echo \"$line\""},
		},
		{
			name:  "control structure with dangerous command",
			input: "if true; then rm -rf /; fi",
			want:  []string{"true", "rm -rf /"},
		},
		{
			name:  "test clause",
			input: "if [[ -f foo ]]; then echo yes; fi",
			want:  []string{"echo yes"},
		},
		// Test commands: dangerous command substitutions inside must still be extracted
		{
			name:  "dangerous cmd subst in [ ] is extracted",
			input: "[ $(dangerous_cmd) ]",
			want:  []string{"dangerous_cmd"},
		},
		{
			name:  "dangerous cmd subst in [[ ]] is extracted",
			input: "[[ $(dangerous_cmd) == foo ]]",
			want:  []string{"dangerous_cmd"},
		},
		{
			name:  "dangerous cmd subst in test is extracted",
			input: "test $(dangerous_cmd)",
			want:  []string{"dangerous_cmd"},
		},
		{
			name:  "compound script with if [ ] emits only inner commands",
			input: "if [ -z \"$CADENCE_ROOT\" ] && [ -f \".claude-plugin/plugin.json\" ]; then CADENCE_ROOT=\"$(pwd)\"; fi",
			want:  []string{"pwd"},
		},
		{
			name:  "test command standalone skipped",
			input: "test -z \"$VAR\"",
			want:  []string{"test -z \"$VAR\""}, // fallback: single element returned as-is
		},
		// Variable assignments — should not emit the assignment wrapper
		{
			name:  "variable assignment with command substitution",
			input: "VAR=$(git status) && echo $VAR",
			want:  []string{"git status", "echo $VAR"},
		},
		{
			name:  "pure variable assignment without command",
			input: "FOO=bar",
			want:  []string{"FOO=bar"}, // fallback: single element returned as-is
		},
		{
			name:  "variable assignment before command strips assignment",
			input: "FOO=bar cmd arg",
			want:  []string{"cmd arg"},
		},
		{
			name:  "export with command substitution",
			input: "export VAR=$(whoami) && echo done",
			want:  []string{"export VAR=$(whoami)", "whoami", "echo done"},
		},
		{
			name:  "multiple assignments with command substitution",
			input: "A=$(cmd1) && B=$(cmd2) && echo $A $B",
			want:  []string{"cmd1", "cmd2", "echo $A $B"},
		},
		// Security: dangerous commands inside assignments must still be extracted
		{
			name:  "dangerous command in assignment is extracted",
			input: "DANGEROUS=$(rm -rf /) && echo done",
			want:  []string{"rm -rf /", "echo done"},
		},
		{
			name:  "multiple pure assignments no command",
			input: "A=1 B=2",
			want:  []string{"A=1 B=2"}, // fallback: single element returned as-is
		},
		{
			name:  "single assignment with command substitution",
			input: "A=$(dangerous_cmd)",
			want:  []string{"dangerous_cmd"},
		},
		{
			name:  "env var prefix before command strips assignment",
			input: "PATH=/tmp:$PATH cmd",
			want:  []string{"cmd"},
		},
		{
			name:  "env var with subshell before command emits both",
			input: "FOO=$(dangerous_cmd) safe_cmd arg",
			want:  []string{"safe_cmd arg", "dangerous_cmd"},
		},
		{
			name:  "multiple env vars with subshells before command",
			input: "A=$(cmd1) B=$(cmd2) main_cmd",
			want:  []string{"main_cmd", "cmd1", "cmd2"},
		},
		{
			name:  "MAGICK_FONT_PATH env var before magick command",
			input: "MAGICK_FONT_PATH=/fonts magick -resize 100x100 in.png out.png",
			want:  []string{"magick -resize 100x100 in.png out.png"},
		},
		{
			name:  "env var compound with && strips assignments",
			input: "MAGICK_FONT_PATH=/fonts magick in.png out.png && file out.png && magick identify out.png",
			want:  []string{"magick in.png out.png", "file out.png", "magick identify out.png"},
		},
		{
			name:  "declare with command substitution emits both",
			input: "declare -x FOO=$(cmd)",
			want:  []string{"declare -x FOO=$(cmd)", "cmd"},
		},
		{
			name:  "nested substitution in assignment",
			input: "X=$(echo $(rm -rf /)) && ls",
			want:  []string{"echo $(rm -rf /)", "rm -rf /", "ls"},
		},
		// bash -c / sh -c extraction
		{
			name:  "bash -c extracts inner command",
			input: "bash -c 'rm -rf /'",
			want:  []string{"rm -rf /"},
		},
		{
			name:  "sh -c extracts inner command",
			input: "sh -c 'echo hello'",
			want:  []string{"echo hello"},
		},
		{
			name:  "bash -c with double quotes",
			input: `bash -c "rm -rf /"`,
			want:  []string{"rm -rf /"},
		},
		{
			name:  "bash -c with unquoted arg",
			input: "bash -c ls",
			want:  []string{"ls"},
		},
		{
			name:  "bash -c with compound inner command",
			input: "bash -c 'git status && rm -rf /'",
			want:  []string{"git status", "rm -rf /"},
		},
		{
			name:  "bash -c in compound with other commands",
			input: "bash -c 'rm -rf /' && git status",
			want:  []string{"rm -rf /", "git status"},
		},
		{
			name:  "bash -c with flags before -c",
			input: "bash -x -c 'dangerous_cmd'",
			want:  []string{"dangerous_cmd"},
		},
		{
			name:  "bash -xc combined flags",
			input: "bash -xc 'dangerous_cmd'",
			want:  []string{"dangerous_cmd"},
		},
		{
			name:  "bash -cx combined flags (c not last)",
			input: "bash -cx 'dangerous_cmd'",
			want:  []string{"dangerous_cmd"},
		},
		{
			name:  "bash -- -c treated as bare (-- terminates options)",
			input: "bash -- -c 'cmd'",
			want:  []string{"bash -- -c 'cmd'"},
		},
		{
			name:  "bash -c with dynamic arg before -c fails closed",
			input: `bash "$FLAG" -c 'rm -rf /'`,
			want:  []string{`bash "$FLAG" -c 'rm -rf /'`},
		},
		{
			name:  "bare bash with script emitted in compound",
			input: "bash script.sh && rm -rf /",
			want:  []string{"bash script.sh", "rm -rf /"},
		},
		{
			name:  "bare bash alone returns as-is (fallback)",
			input: "bash script.sh",
			want:  []string{"bash script.sh"},
		},
		{
			name:  "bare sh emitted as normal command",
			input: "sh -x script.sh",
			want:  []string{"sh -x script.sh"},
		},
		{
			name:  "nested bash -c recursion",
			input: `bash -c 'bash -c "rm -rf /"'`,
			want:  []string{"rm -rf /"},
		},
		{
			name:  "bash -c with dynamic arg falls back",
			input: `bash -c "$CMD"`,
			want:  []string{`bash -c "$CMD"`},
		},
		{
			name:  "/bin/bash -c extracts inner",
			input: "/bin/bash -c 'dangerous'",
			want:  []string{"dangerous"},
		},
		{
			name:  "/bin/sh -c extracts inner",
			input: "/bin/sh -c 'dangerous'",
			want:  []string{"dangerous"},
		},
		{
			name:  "bash -c with inner subshell",
			input: "bash -c 'echo $(whoami)'",
			want:  []string{"echo $(whoami)", "whoami"},
		},
		{
			name:  "bash without args treated as bare (fallback)",
			input: "bash",
			want:  []string{"bash"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Split(tt.input)
			if !sliceEqual(got, tt.want) {
				t.Errorf("Split(%q)\n  got:  %v\n  want: %v", tt.input, got, tt.want)
			}
		})
	}
}

func sliceEqual(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
