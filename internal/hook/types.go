// Package hook defines the Claude Code hook input/output types.
package hook

// Input is the JSON payload received from Claude Code via stdin.
type Input struct {
	SessionID      string          `json:"session_id"`
	TranscriptPath string          `json:"transcript_path"`
	Cwd            string          `json:"cwd"`
	PermissionMode string          `json:"permission_mode"`
	HookEventName  string          `json:"hook_event_name"`
	ToolName       string          `json:"tool_name"`
	ToolInput      ToolInput       `json:"tool_input"`
	ToolUseID      string          `json:"tool_use_id"`
}

// ToolInput contains the tool-specific fields.
// Fields are optional depending on tool_name.
type ToolInput struct {
	// Bash
	Command     string `json:"command,omitempty"`
	Description string `json:"description,omitempty"`

	// Read, Edit, Write
	FilePath string `json:"file_path,omitempty"`

	// Edit
	OldString  string `json:"old_string,omitempty"`
	NewString  string `json:"new_string,omitempty"`
	ReplaceAll bool   `json:"replace_all,omitempty"`

	// Write
	Content string `json:"content,omitempty"`

	// Grep, Glob
	Pattern string `json:"pattern,omitempty"`
	Path    string `json:"path,omitempty"`
}

// Output is the JSON response written to stdout.
type Output struct {
	HookSpecificOutput *HookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

// HookSpecificOutput contains the permission decision for PreToolUse hooks.
type HookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}
