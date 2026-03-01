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
			want:  []string{"sleep 5"},
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
			name:  "backslash escape",
			input: `echo hello\&\& world`,
			want:  []string{`echo hello\&\& world`},
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
			name:  "subshell not split",
			input: "echo $(git status && git log)",
			want:  []string{"echo $(git status && git log)"},
		},
		{
			name:  "nested subshell not split",
			input: "echo $(a && $(b || c))",
			want:  []string{"echo $(a && $(b || c))"},
		},
		{
			name:  "subshell then operator",
			input: "echo $(cat file) && rm -rf /",
			want:  []string{"echo $(cat file)", "rm -rf /"},
		},
		{
			name:  "backtick not split",
			input: "echo `git status && git log`",
			want:  []string{"echo `git status && git log`"},
		},
		{
			name:  "double semicolons produce no empty parts",
			input: "ls ;; pwd",
			want:  []string{"ls", "pwd"},
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
			name:  "unbalanced single quote treats rest as quoted",
			input: "echo 'hello && rm -rf /",
			want:  []string{"echo 'hello && rm -rf /"},
		},
		{
			name:  "pipe with redirect",
			input: "cmd 2>&1 | grep error",
			want:  []string{"cmd 2>&1", "grep error"},
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
