package mcptool

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/types"
)

// Regression tests for the review findings on this branch. Grouped by defect
// rather than by reviewer, since three reviewers converged on several of them.

// --- Safety: value selection must fail closed -------------------------------

// TestSafeCandidateValue_PrefersReadOnlyAndFailsClosed covers the most serious
// finding: selection took candidates[0] blindly, so a discriminator declaring
// ["delete", "read"] handed the probe its DESTRUCTIVE branch as a "benign"
// filler. Enum order carries no safety information.
//
// This branch made the hazard worse before this fix. Previously benignValue
// returned the placeholder "test", which a server rejects harmlessly; candidate
// inference replaced that with a real, valid operation.
func TestSafeCandidateValue_PrefersReadOnlyAndFailsClosed(t *testing.T) {
	destructiveFirst := paramInfo{name: "action", typ: "string", candidates: []string{"delete", "read"}}
	got, ok := destructiveFirst.safeCandidateValue()
	if !ok || got != "read" {
		t.Errorf("safeCandidateValue() = %q,%v; want \"read\",true — declaration order must not decide safety", got, ok)
	}

	// Nothing recognisably read-only: contribute NOTHING rather than guess.
	allDestructive := paramInfo{name: "action", typ: "string", candidates: []string{"delete", "update"}}
	if v, ok := allDestructive.safeCandidateValue(); ok {
		t.Errorf("safeCandidateValue() = %q,true; want no value — an unrecognised operation must fail closed", v)
	}
	if v := benignValue(allDestructive); v != "test" {
		t.Errorf("benignValue = %v; want the rejected placeholder \"test\"", v)
	}
	// And the payload prefix must not lead with a destructive branch either.
	if got := payloadVariants(allDestructive, "PAYLOAD"); len(got) != 1 || got[0] != "PAYLOAD" {
		t.Errorf("payloadVariants = %v; want the bare payload only", got)
	}
}

// TestTypedEnumValue_NonStringEnums covers the numeric/boolean enum gap: every
// enum member is rendered as a string by schemaEnum, so a typed enum previously
// fell through to the generic 1/true placeholder and was rejected by a server
// validating against the declared set.
func TestTypedEnumValue_NonStringEnums(t *testing.T) {
	if v := benignValue(paramInfo{name: "level", typ: "integer", candidates: []string{"3", "7"}}); v != 3 {
		t.Errorf("benignValue(integer enum) = %#v, want 3", v)
	}
	if v := benignValue(paramInfo{name: "ratio", typ: "number", candidates: []string{"0.5"}}); v != 0.5 {
		t.Errorf("benignValue(number enum) = %#v, want 0.5", v)
	}
	if v := benignValue(paramInfo{name: "force", typ: "boolean", candidates: []string{"false"}}); v != false {
		t.Errorf("benignValue(boolean enum) = %#v, want false", v)
	}
	// No enum: the generic placeholders stand.
	if v := benignValue(paramInfo{name: "n", typ: "integer"}); v != 1 {
		t.Errorf("benignValue(no enum) = %#v, want 1", v)
	}
}

// --- Safety: readIntent must not trust a value it will not send -------------

// TestReadIntent_OptionalDiscriminatorIsNotTrusted covers a hazard with a severe
// consequence: benignArgs sends only REQUIRED parameters, so an optional
// discriminator's preferred value never reaches the server. The server applies
// its own default, which may be a write — while the probe, having read "read"
// off the optional parameter, selects a sensitive absolute path as the payload.
func TestReadIntent_OptionalDiscriminatorIsNotTrusted(t *testing.T) {
	// `action` offers read but is NOT required; `path` is.
	tool := map[string]any{
		"name":        "handler",
		"description": "Handles the request",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action": map[string]any{"type": "string", "enum": []any{"read", "write"}},
				"path":   strProp(),
			},
			"required": []any{"path"},
		},
	}
	params := toolParams(tool)
	if readIntent(tool, params) {
		t.Error("readIntent = true from an OPTIONAL discriminator; benignArgs never sends it, so the server's default decides")
	}

	// Required: now the value we read is the value we transmit, so it counts.
	tool["parameters"].(map[string]any)["required"] = []any{"action", "path"}
	if !readIntent(tool, toolParams(tool)) {
		t.Error("readIntent = false for a REQUIRED read discriminator; the narrowing must not disable the signal")
	}
}

// --- Safety: mutation detection must not fail open --------------------------

// TestVerbMatching_IdentifiersAreVisible covers a defect that made every tool
// NAME contribute nothing to the read/mutation decision. `\b` sits between a
// word and a non-word character, and `_` is a word character — so `\bread\b`
// never matched `read_file` and `\bdelete\b` never matched `delete_item`.
func TestVerbMatching_IdentifiersAreVisible(t *testing.T) {
	for _, name := range []string{"read_file", "get_config", "fetchRecord", "list-items"} {
		if !readVerbRE.MatchString(normaliseIdentifiers(name)) {
			t.Errorf("read verb not found in identifier %q", name)
		}
	}
	for _, name := range []string{"delete_item", "deleteUser", "update_record", "wipe-disk", "resetCounters"} {
		if !mutationVerbRE.MatchString(normaliseIdentifiers(name)) {
			t.Errorf("mutation verb not found in identifier %q — a destructive tool would be eligible for read payloads", name)
		}
	}
}

// TestVerbMatching_DoubledConsonantInflections covers gerunds and past tenses a
// suffix group cannot produce. `(s|es|ing|ed)?` yields "runing", never "running";
// RE2 has no backreferences, so the doubling rule is generated per stem instead.
//
// The worst measured case was "Running the query": read matched (via "query")
// while mutation did not, classifying a command runner as read-only.
func TestVerbMatching_DoubledConsonantInflections(t *testing.T) {
	mutating := []string{
		"Running the query", "Dropping the table", "Setting the value",
		"Putting the object", "Resetting the counters", "Stores the record",
		"Deleting the entry", "Wrote the file", "Ran the migration",
	}
	for _, desc := range mutating {
		if !mutationVerbRE.MatchString(normaliseIdentifiers(desc)) {
			t.Errorf("mutation verb not found in %q", desc)
		}
	}
	// "Got" is the irregular past of the READ verb "get", so it belongs here.
	reading := []string{"Getting the config", "Fetches the record", "Retrieving the document", "Got the lock"}
	for _, desc := range reading {
		if !readVerbRE.MatchString(normaliseIdentifiers(desc)) {
			t.Errorf("read verb not found in %q", desc)
		}
	}
}

// TestReadIntent_DestructiveVerbsDisqualify covers the destructive vocabulary
// that was missing outright. A tool that reads AND destroys must never receive a
// payload naming a sensitive absolute path.
func TestReadIntent_DestructiveVerbsDisqualify(t *testing.T) {
	for _, desc := range []string{
		"Reads the log and clears it",
		"Reads then wipes the buffer",
		"Reads and resets the counters",
		"Read the file then format the volume",
		"Reads and flushes the cache",
		"Gets the entry and purges stale ones",
		"Retrieves the archive and erases the original",
	} {
		tool := docTool("thing", desc, map[string]any{"path": strProp()}, "path")
		if readIntent(tool, toolParams(tool)) {
			t.Errorf("readIntent = true for %q; a destructive verb must disqualify", desc)
		}
	}

	// The paired positive: a genuine reader must still qualify, or the widened
	// vocabulary has re-darkened the file-content oracle this branch exists to
	// switch on.
	for _, desc := range []string{
		"Reads file contents from the filesystem. Supports relative and absolute paths.",
		"Get a configuration value from the system",
		"Retrieves the requested document",
	} {
		tool := docTool("read_file", desc, map[string]any{"path": strProp()}, "path")
		if !readIntent(tool, toolParams(tool)) {
			t.Errorf("readIntent = false for genuine reader %q", desc)
		}
	}
}

// --- Correctness: discovery must not invoke pointlessly ---------------------

// countingInvoker records how many times CallTool ran.
type countingInvoker struct {
	*mockTarget
	calls atomic.Int32
}

func (c *countingInvoker) CallTool(ctx context.Context, name string, args map[string]any) (types.ToolResult, error) {
	c.calls.Add(1)
	return c.mockTarget.CallTool(ctx, name, args)
}

func newCountingInvoker(reply func(string, map[string]any) types.ToolResult) *countingInvoker {
	return &countingInvoker{mockTarget: &mockTarget{call: reply}}
}

// TestDiscoverToolValues_NoCallWhenAdoptionImpossible covers an invocation made
// purely to be discarded. The adoption test — exactly one uncandidated parameter,
// because a response is not attributed per parameter — used to run AFTER the
// call. With two or more unknowns the probe invoked a real tool on a customer's
// system and then threw the response away.
func TestDiscoverToolValues_NoCallWhenAdoptionImpossible(t *testing.T) {
	inv := newCountingInvoker(func(string, map[string]any) types.ToolResult {
		return types.ToolResult{Text: "must be one of: read, write"}
	})
	params := []paramInfo{
		{name: "action", typ: "string", required: true},
		{name: "mode", typ: "string", required: true},
	}
	out := discoverToolValues(context.Background(), inv, "t", params)
	if n := inv.calls.Load(); n != 0 {
		t.Errorf("CallTool ran %d time(s) with two uncandidated params; want 0 — the response cannot be attributed, so the call is a side effect with no benefit", n)
	}
	for _, p := range out {
		if len(p.candidates) != 0 {
			t.Errorf("param %q adopted candidates despite ambiguity", p.name)
		}
	}
}

// TestDiscoverToolValues_AdoptsFromRejection is the paired positive.
func TestDiscoverToolValues_AdoptsFromRejection(t *testing.T) {
	inv := newCountingInvoker(func(_ string, args map[string]any) types.ToolResult {
		return types.ToolResult{Text: fmt.Sprintf("Invalid action %q. Must be one of: read, write, delete", args["action"])}
	})
	params := []paramInfo{{name: "action", typ: "string", required: true}}
	out := discoverToolValues(context.Background(), inv, "t", params)
	if inv.calls.Load() != 1 {
		t.Fatalf("CallTool ran %d times, want 1", inv.calls.Load())
	}
	got := strings.Join(out[0].candidates, ",")
	if got != "read,write,delete" {
		t.Errorf("candidates = %q, want \"read,write,delete\"", got)
	}
}

// TestDiscoverToolValues_NeverAdoptsTheValueWeSent covers the flaw that defeated
// discovery on exactly the message shape motivating it. A rejection routinely
// quotes the value it refused — the quoted shape matched first, so the probe
// adopted "test": the placeholder it had just sent and the server had just
// rejected. Every later call was then rejected identically.
func TestDiscoverToolValues_NeverAdoptsTheValueWeSent(t *testing.T) {
	inv := newCountingInvoker(func(_ string, args map[string]any) types.ToolResult {
		return types.ToolResult{Text: fmt.Sprintf("Invalid action '%v'. Must be one of: read, write, delete", args["action"])}
	})
	params := []paramInfo{{name: "action", typ: "string", required: true}}
	out := discoverToolValues(context.Background(), inv, "t", params)
	for _, c := range out[0].candidates {
		if strings.EqualFold(c, "test") {
			t.Fatalf("adopted %q — the placeholder we sent and the server refused; candidates=%v", c, out[0].candidates)
		}
	}
	if len(out[0].candidates) == 0 {
		t.Fatal("adopted nothing; the accepted list was present in the rejection")
	}
}

// TestPathTraversal_NoDiscoveryOnUnprobeableTool covers the eager-invocation
// finding: discovery ran per policy-permitted tool, before the path-parameter
// filter. A tool whose only string parameter is non-path received a live call
// even though the probe then sent it zero payloads — an invocation with no
// corresponding attempt record.
func TestPathTraversal_NoDiscoveryOnUnprobeableTool(t *testing.T) {
	lookup := docTool("lookup_user", "Look up a user", map[string]any{"username": strProp()}, "username")
	inv := &countingInvoker{mockTarget: &mockTarget{
		tools: []map[string]any{lookup},
		call: func(string, map[string]any) types.ToolResult {
			return types.ToolResult{Text: "must be one of: alice, bob"}
		},
	}}

	attempts, err := newPathTraversalProbe(t).Probe(context.Background(), inv)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if n := inv.calls.Load(); n != 0 {
		t.Errorf("CallTool ran %d time(s) on a tool with no path-shaped parameter; want 0", n)
	}
	if len(attempts) != 0 {
		t.Errorf("got %d attempts for an unprobeable tool, want 0", len(attempts))
	}
}

// --- Mining: natural English lists -----------------------------------------

// TestMineCandidateValues_ConnectiveLists covers parenthetical lists ending in a
// connective, which failed wholesale because of the space in "or delete".
func TestMineCandidateValues_ConnectiveLists(t *testing.T) {
	cases := map[string]string{
		"The action to perform (read, write, or delete)": "read,write,delete",
		"The action to perform (read, write and delete)": "read,write,delete",
		"Whether to grant or revoke (grant or revoke)":   "grant,revoke",
		"The action to perform (read, write, delete)":    "read,write,delete",
	}
	for frag, want := range cases {
		got := strings.Join(mineCandidateValues(frag), ",")
		if got != want {
			t.Errorf("mineCandidateValues(%q) = %q, want %q", frag, got, want)
		}
	}

	// The false-positive guard this branch already added must still hold: loose
	// alternation matching previously turned a sandbox path into the tokens
	// "tmp" and "safe". Relaxing the separator must not relax the token shape or
	// the whole-group anchor.
	for _, frag := range []string{
		"Read a file (only files in /tmp/safe/ allowed)",
		"The path to read (must be inside the workspace)",
	} {
		if got := mineCandidateValues(frag); len(got) != 0 {
			t.Errorf("mineCandidateValues(%q) = %v, want none — prose and paths are not value lists", frag, got)
		}
	}
}

// TestToolParams_MinesPropertyDescription covers the source most SDKs actually
// use: per-argument documentation on the schema property itself, rather than an
// "Args:" block in the tool-level description. It needs no attribution guessing —
// the text belongs to that parameter by construction.
func TestToolParams_MinesPropertyDescription(t *testing.T) {
	tool := map[string]any{
		"name":        "file_manager",
		"description": "Manage files",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action": map[string]any{
					"type":        "string",
					"description": "The action to perform (read, write, delete)",
				},
				"path": strProp(),
			},
			"required": []any{"action", "path"},
		},
	}
	var action paramInfo
	for _, p := range toolParams(tool) {
		if p.name == "action" {
			action = p
		}
	}
	if got := strings.Join(action.candidates, ","); got != "read,write,delete" {
		t.Errorf("candidates from property description = %q, want \"read,write,delete\"", got)
	}
	// And the whole point: the read branch is selected, not the first-declared one.
	if v, ok := action.safeCandidateValue(); !ok || v != "read" {
		t.Errorf("safeCandidateValue = %q,%v; want \"read\",true", v, ok)
	}
}
