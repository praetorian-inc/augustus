package mcptool

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/types"
)

func TestReadIntent(t *testing.T) {
	tests := []struct {
		name string
		tool map[string]any
		want bool
	}{
		{
			// DVMCP challenge 10's shape: a read verb, no mutation vocabulary.
			name: "read verb and no mutation verb",
			tool: docTool("get_config", "Get a configuration value from the system\n\nArgs:\n    config_name: The name of the configuration to retrieve\n",
				map[string]any{"config_name": strProp()}, "config_name"),
			want: true,
		},
		{
			// DVMCP challenge 2's shape.
			name: "read_file is a read",
			tool: docTool("read_file", "Read a file from the system (restricted to safe files only)\n",
				map[string]any{"filename": strProp()}, "filename"),
			want: true,
		},
		{
			// DVMCP challenge 3's shape: the tool as a whole can mutate, so its
			// name and description are disqualifying -- but the discriminator
			// makes THIS call a read.
			name: "mutating tool admitted via read discriminator",
			tool: docTool("file_manager", "File manager tool that can read, write, and delete files\n\nArgs:\n    action: The action to perform (read, write, delete)\n    path: The file path to operate on\n",
				map[string]any{"action": strProp(), "path": strProp()}, "action", "path"),
			want: true,
		},
		{
			// The safety case: mutation vocabulary present, no read discriminator
			// to rescue it. Sending a read payload here would target a sensitive
			// path on a tool that writes.
			name: "mutating tool with no read discriminator",
			tool: docTool("save_report", "Write a report to disk and delete the previous one\n\nArgs:\n    path: Where to write it\n",
				map[string]any{"path": strProp()}, "path"),
			want: false,
		},
		{
			name: "no verbs at all",
			tool: docTool("handle", "Handles a thing\n", map[string]any{"path": strProp()}, "path"),
			want: false,
		},
		{
			// "download" must not match via the "load" substring.
			name: "read verb matched on word boundary",
			tool: docTool("download_file", "Download a file\n", map[string]any{"path": strProp()}, "path"),
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := readIntent(tc.tool, toolParams(tc.tool)); got != tc.want {
				t.Errorf("readIntent = %v, want %v", got, tc.want)
			}
		})
	}
}

func isReadPayloadSet(payloads []pathTraversalPayload) bool {
	for _, p := range payloads {
		if p.isWrite {
			return false
		}
	}
	return len(payloads) > 0
}

func TestPayloadsFor_AnnotationAbsentUsesDeclaredReadIntent(t *testing.T) {
	p := &PathTraversal{}

	// Annotation-absent but self-declared read-only: the whole point of the
	// change. Before this, every annotation-less server got write payloads only
	// and the file-content oracle never ran.
	readish := docTool("get_config", "Get a configuration value from the system\n",
		map[string]any{"config_name": strProp()}, "config_name")
	if !isReadPayloadSet(p.payloadsFor(readish, toolParams(readish))) {
		t.Error("annotation-absent read-intent tool got write payloads, want read payloads")
	}

	// Mutation vocabulary present: stays on the write-safe canary path.
	writeish := docTool("save_report", "Write a report to disk\n",
		map[string]any{"path": strProp()}, "path")
	if isReadPayloadSet(p.payloadsFor(writeish, toolParams(writeish))) {
		t.Error("write-intent tool got read payloads; a sensitive path could be overwritten")
	}
}

func TestPayloadsFor_ExplicitAnnotationsStillWin(t *testing.T) {
	p := &PathTraversal{}

	// A ReadOnly annotation remains sufficient on its own, with no read verb
	// anywhere in the metadata.
	annotated := docTool("handle", "Handles a thing\n", map[string]any{"path": strProp()}, "path")
	annotated["annotations"] = types.MCPToolAnnotations{ReadOnly: true}
	if !isReadPayloadSet(p.payloadsFor(annotated, toolParams(annotated))) {
		t.Error("ReadOnly-annotated tool did not get read payloads")
	}

	// Opting out restores the pre-change behaviour: inference is ignored and only
	// an explicit annotation admits read payloads.
	strict := &PathTraversal{requireReadOnlyAnnotation: true}
	readish := docTool("get_config", "Get a configuration value from the system\n",
		map[string]any{"config_name": strProp()}, "config_name")
	if isReadPayloadSet(strict.payloadsFor(readish, toolParams(readish))) {
		t.Error("requireReadOnlyAnnotation=true still used inferred read intent")
	}
	// ...but an explicit annotation must still work under the strict setting.
	if !isReadPayloadSet(strict.payloadsFor(annotated, toolParams(annotated))) {
		t.Error("requireReadOnlyAnnotation=true ignored an explicit ReadOnly annotation")
	}
}

// TestReadIntent_HandlesInflectedVerbs is the regression for a false negative
// found only by testing against a non-DVMCP target.
//
// English tool descriptions are overwhelmingly third-person — "Reads file
// contents", "Returns user information" — and a stem-only word-boundary pattern
// matches none of them. Measured on an independent lab: `read_file` described as
// "Reads file contents from the filesystem." failed readIntent, received
// write-canary payloads instead of read payloads, and a documented path traversal
// went undetected. DVMCP uses bare imperatives ("Read a file from the system"),
// which matched — so the original corpus could not surface this at all.
func TestReadIntent_HandlesInflectedVerbs(t *testing.T) {
	readish := []string{
		"Reads file contents from the filesystem. Supports relative and absolute paths.",
		"Gets a configuration value",
		"Retrieves the requested document",
		"Fetching a remote record",
		"Searches the user database for matching usernames.",
	}
	for _, desc := range readish {
		tool := docTool("thing", desc, map[string]any{"path": strProp()}, "path")
		if !readIntent(tool, toolParams(tool)) {
			t.Errorf("readIntent = false for %q, want true", desc)
		}
	}

	// The safety half must inflect too: missing "writes" or "deletes" where only
	// the stem was matched would admit a write-capable tool to the read path.
	writeish := []string{
		"Writes the report to disk",
		"Deletes the previous entry",
		"Executes a system command",
		"Updates the stored record",
		"Reads a file and then removes it",
	}
	for _, desc := range writeish {
		tool := docTool("thing", desc, map[string]any{"path": strProp()}, "path")
		if readIntent(tool, toolParams(tool)) {
			t.Errorf("readIntent = true for %q, want false; mutation vocabulary must disqualify", desc)
		}
	}
}
