package mcptool

import "testing"

// docTool builds a tool whose description carries an Args: block, the shape
// docstring-derived MCP descriptions actually take.
func docTool(name, desc string, props map[string]any, required ...string) map[string]any {
	req := make([]any, 0, len(required))
	for _, r := range required {
		req = append(req, r)
	}
	return map[string]any{
		"name":        name,
		"description": desc,
		"parameters": map[string]any{
			"type":       "object",
			"properties": props,
			"required":   req,
		},
	}
}

func strProp() map[string]any { return map[string]any{"type": "string"} }

func findParam(t *testing.T, params []paramInfo, name string) paramInfo {
	t.Helper()
	for _, p := range params {
		if p.name == name {
			return p
		}
	}
	t.Fatalf("param %q not found in %+v", name, params)
	return paramInfo{}
}

func TestParamDoc_ScopesToTheNamedParameter(t *testing.T) {
	desc := "File manager tool\n\nArgs:\n    action: The action to perform (read, write, delete)\n    path: The file path to operate on\n"

	if got, want := paramDoc(desc, "action"), "The action to perform (read, write, delete)"; got != want {
		t.Errorf("action doc = %q, want %q", got, want)
	}
	if got, want := paramDoc(desc, "path"), "The file path to operate on"; got != want {
		t.Errorf("path doc = %q, want %q", got, want)
	}
	// A parameter the description never documents must not inherit another's.
	if got := paramDoc(desc, "mode"); got != "" {
		t.Errorf("undocumented param doc = %q, want empty", got)
	}
	if got := paramDoc("", "action"); got != "" {
		t.Errorf("empty description doc = %q, want empty", got)
	}
}

func TestMineCandidateValues(t *testing.T) {
	tests := []struct {
		name string
		frag string
		want []string
	}{
		{
			name: "quoted list",
			frag: "The command to execute (only 'ls', 'pwd', 'whoami', 'date' allowed)",
			want: []string{"ls", "pwd", "whoami", "date"},
		},
		{
			name: "parenthesised comma list",
			frag: "The action to perform (read, write, delete)",
			want: []string{"read", "write", "delete"},
		},
		{
			name: "slash alternatives",
			frag: "The permission to grant or revoke (grant/revoke)",
			want: []string{"grant", "revoke"},
		},
		{
			name: "quoted wins over surrounding prose",
			frag: `The remote system to access (e.g., "database", "webserver", "fileserver")`,
			want: []string{"database", "webserver", "fileserver"},
		},
		// False-positive guards: a wrong value is no better than the placeholder
		// it would replace, so prose and paths must yield nothing.
		{
			name: "path prose yields nothing",
			frag: "The file to read (only files in /tmp/safe/ allowed)",
			want: nil,
		},
		{
			name: "free prose yields nothing",
			frag: "The user to modify permissions for",
			want: nil,
		},
		{
			name: "multi-word parenthetical yields nothing",
			frag: "The target host (must be reachable from the server)",
			want: nil,
		},
		{
			name: "empty fragment",
			frag: "",
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mineCandidateValues(tc.frag)
			if len(got) != len(tc.want) {
				t.Fatalf("mineCandidateValues(%q) = %v, want %v", tc.frag, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("mineCandidateValues(%q) = %v, want %v", tc.frag, got, tc.want)
				}
			}
		})
	}
}

func TestToolParams_SchemaEnumBeatsDescription(t *testing.T) {
	// The schema is authoritative: when it declares an enum, prose is ignored.
	tool := docTool("t", "Args:\n    mode: The mode (fromprose)\n",
		map[string]any{"mode": map[string]any{
			"type": "string",
			"enum": []any{"fromschema", "other"},
		}}, "mode")

	p := findParam(t, toolParams(tool), "mode")
	if len(p.candidates) == 0 || p.candidates[0] != "fromschema" {
		t.Fatalf("candidates = %v, want schema enum first", p.candidates)
	}
}

func TestToolParams_MinesDescriptionWhenNoEnum(t *testing.T) {
	// Shape taken verbatim from DVMCP challenge 3, whose schema declares no
	// enum at all -- the case that made the sink unreachable.
	tool := docTool("file_manager",
		"File manager tool that can read, write, and delete files\n\nArgs:\n    action: The action to perform (read, write, delete)\n    path: The file path to operate on\n",
		map[string]any{"action": strProp(), "path": strProp()}, "action", "path")

	params := toolParams(tool)

	action := findParam(t, params, "action")
	if len(action.candidates) == 0 || action.candidates[0] != "read" {
		t.Fatalf("action candidates = %v, want [read write delete]", action.candidates)
	}
	// "The file path to operate on" carries no enumerable values; mining it must
	// not invent one, or the traversal payload would be replaced by a guess.
	path := findParam(t, params, "path")
	if len(path.candidates) != 0 {
		t.Fatalf("path candidates = %v, want none", path.candidates)
	}
}

func TestBenignValue_PrefersCandidateThenFallsBack(t *testing.T) {
	withCandidate := paramInfo{name: "action", typ: "string", candidates: []string{"read", "write"}}
	if got := benignValue(withCandidate); got != "read" {
		t.Errorf("benignValue(with candidate) = %v, want read", got)
	}

	// No candidate: the generic placeholder is still correct.
	if got := benignValue(paramInfo{name: "q", typ: "string"}); got != "test" {
		t.Errorf("benignValue(string, no candidate) = %v, want test", got)
	}

	// A mined token is text; coercing it into a non-string parameter would break
	// argument validation rather than satisfy it.
	numeric := paramInfo{name: "count", typ: "integer", candidates: []string{"read"}}
	if got := benignValue(numeric); got != 1 {
		t.Errorf("benignValue(integer with candidate) = %v, want 1", got)
	}
	if got := benignValue(paramInfo{name: "flag", typ: "boolean"}); got != true {
		t.Errorf("benignValue(boolean) = %v, want true", got)
	}
}

func TestBenignArgs_FillsGatingParamWithDocumentedValue(t *testing.T) {
	tool := docTool("file_manager",
		"Args:\n    action: The action to perform (read, write, delete)\n    path: The file path to operate on\n",
		map[string]any{"action": strProp(), "path": strProp()}, "action", "path")

	args := benignArgs(toolParams(tool), "path", "PAYLOAD")

	if args["path"] != "PAYLOAD" {
		t.Errorf("injected param = %v, want PAYLOAD", args["path"])
	}
	// The whole point: previously this was the placeholder, the server rejected
	// the call, and the sink was never reached.
	if args["action"] != "read" {
		t.Errorf("gating param = %v, want read", args["action"])
	}
}
