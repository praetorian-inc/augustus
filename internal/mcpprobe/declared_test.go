package mcpprobe

import (
	"reflect"
	"testing"
)

// TestDeclaredValues_SchemaEnumWins: a JSON-schema enum is the target's most
// explicit declaration of what it accepts.
func TestDeclaredValues_SchemaEnumWins(t *testing.T) {
	tool := map[string]any{
		"name":        "set_mode",
		"description": "Args:\n    mode: the mode (e.g. \"ignored\")",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"mode": map[string]any{"type": "string", "enum": []any{"read", "write"}},
			},
		},
	}
	got := DeclaredValues(tool, "mode")
	if want := []string{"read", "write"}; !reflect.DeepEqual(got, want) {
		t.Errorf("DeclaredValues() = %v, want %v (schema enum must win over the description)", got, want)
	}
}

// TestDeclaredValues_FromDocstringArgsBlock is the shape FastMCP servers produce:
// per-parameter documentation lives in the TOOL description, not in the parameter
// schema, so values a target documents are only discoverable there. A probe that
// read the schema alone would find nothing to try and would have to fall back to
// guessing.
func TestDeclaredValues_FromDocstringArgsBlock(t *testing.T) {
	tool := map[string]any{
		"name": "remote_access",
		"description": "Execute a command on a remote system\n" +
			"            \n" +
			"            Args:\n" +
			"                system: The remote system to access (e.g., \"database\", \"webserver\", \"fileserver\")\n" +
			"                command: The command to execute on the remote system\n" +
			"                auth_token: Optional authentication token for privileged operations\n",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"system":  map[string]any{"type": "string"},
				"command": map[string]any{"type": "string"},
			},
		},
	}
	got := DeclaredValues(tool, "system")
	want := []string{"database", "webserver", "fileserver"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DeclaredValues() = %v, want %v", got, want)
	}
}

// TestDeclaredValues_SlashAlternatives: a parenthesised slash-separated list is a
// common way to document accepted values without quoting them.
func TestDeclaredValues_SlashAlternatives(t *testing.T) {
	tool := map[string]any{
		"name": "manage_permissions",
		"description": "Manage access permissions\n" +
			"            Args:\n" +
			"                user: The user to modify permissions for\n" +
			"                permission: The permission to grant or revoke (grant/revoke)\n",
		"parameters": map[string]any{
			"type":       "object",
			"properties": map[string]any{"permission": map[string]any{"type": "string"}},
		},
	}
	got := DeclaredValues(tool, "permission")
	if want := []string{"grant", "revoke"}; !reflect.DeepEqual(got, want) {
		t.Errorf("DeclaredValues() = %v, want %v", got, want)
	}
}

// TestDeclaredValues_ParameterSchemaDescription: when the schema does carry a
// per-parameter description, quoted values there count too.
func TestDeclaredValues_ParameterSchemaDescription(t *testing.T) {
	tool := map[string]any{
		"name": "set_tier",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"tier": map[string]any{"type": "string", "description": "one of 'bronze', 'silver' or 'gold'"},
			},
		},
	}
	got := DeclaredValues(tool, "tier")
	if want := []string{"bronze", "silver", "gold"}; !reflect.DeepEqual(got, want) {
		t.Errorf("DeclaredValues() = %v, want %v", got, want)
	}
}

// TestDeclaredValues_OnlyTheNamedParametersLine: values documented for a
// DIFFERENT parameter must not leak into this one, or the probe would submit a
// command string as a system name and misread the resulting error as a denial.
func TestDeclaredValues_OnlyTheNamedParametersLine(t *testing.T) {
	tool := map[string]any{
		"name": "run",
		"description": "Args:\n" +
			"    target: pick \"alpha\" or \"beta\"\n" +
			"    action: pick \"gamma\" or \"delta\"\n",
		"parameters": map[string]any{
			"type":       "object",
			"properties": map[string]any{"target": map[string]any{"type": "string"}},
		},
	}
	got := DeclaredValues(tool, "target")
	if want := []string{"alpha", "beta"}; !reflect.DeepEqual(got, want) {
		t.Errorf("DeclaredValues() = %v, want %v (must not absorb another parameter's values)", got, want)
	}
}

// TestDeclaredValues_NoneDeclared: a target that documents nothing yields nothing.
// The probe must not invent values and pretend the target declared them.
func TestDeclaredValues_NoneDeclared(t *testing.T) {
	tool := map[string]any{
		"name":        "lookup",
		"description": "Look something up",
		"parameters": map[string]any{
			"type":       "object",
			"properties": map[string]any{"q": map[string]any{"type": "string"}},
		},
	}
	if got := DeclaredValues(tool, "q"); len(got) != 0 {
		t.Errorf("DeclaredValues() = %v, want none", got)
	}
}

// TestDeclaredValues_IgnoresProseAndPunctuation: quoted prose is not a value.
func TestDeclaredValues_IgnoresProseAndPunctuation(t *testing.T) {
	tool := map[string]any{
		"name": "note",
		"description": "Args:\n" +
			"    body: free text, for example \"a long sentence with spaces\" or \"\"\n",
		"parameters": map[string]any{
			"type":       "object",
			"properties": map[string]any{"body": map[string]any{"type": "string"}},
		},
	}
	if got := DeclaredValues(tool, "body"); len(got) != 0 {
		t.Errorf("DeclaredValues() = %v, want none (multi-word prose is not a declared value)", got)
	}
}

// TestConventionalPrivilegedNames documents the audited list directly. These are
// names any pentester would try on ANY target, which is exactly why using them is
// legitimate where copying a value out of a specific server's source is not.
func TestConventionalPrivilegedNames(t *testing.T) {
	got := ConventionalPrivilegedNames()
	if len(got) == 0 {
		t.Fatal("ConventionalPrivilegedNames() is empty")
	}
	// The list must contain the canonical authority names and nothing
	// target-specific.
	for _, want := range []string{"admin", "administrator", "root", "superuser", "system"} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ConventionalPrivilegedNames() missing conventional name %q (have %v)", want, got)
		}
	}
	// Guard against the list quietly growing into a corpus-specific wordlist.
	if len(got) > 20 {
		t.Errorf("ConventionalPrivilegedNames() has %d entries; it must stay a small conventional set, not a wordlist", len(got))
	}
}
