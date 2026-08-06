package mcpprimitive

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// mockTarget implements types.Generator + types.MCPPrimitiveReader +
// types.MCPReconnaissance. It records every primitive request so a test can
// assert WHICH payloads the probe derived, not just how they scored.
type mockTarget struct {
	inv    *types.MCPInventory
	invErr error
	// invCalls counts live enumerations, so a test can assert that a stored
	// inventory was REUSED rather than inferring it from a nil error — which
	// resolveInventories also returns when it falls back to the stored one.
	invCalls int

	read   func(uri string) (types.MCPResourceResult, error)
	prompt func(name string, args map[string]string) (types.MCPPromptResult, error)

	readURIs    []string
	promptCalls []promptCall
}

type promptCall struct {
	name string
	args map[string]string
}

func (m *mockTarget) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (m *mockTarget) ClearHistory()       {}
func (m *mockTarget) Name() string        { return "mock" }
func (m *mockTarget) Description() string { return "mock" }

func (m *mockTarget) MCPInventory(context.Context) (*types.MCPInventory, error) {
	m.invCalls++
	if m.invErr != nil {
		return nil, m.invErr
	}
	return m.inv, nil
}

func (m *mockTarget) ReadResource(_ context.Context, uri string) (types.MCPResourceResult, error) {
	m.readURIs = append(m.readURIs, uri)
	if m.read == nil {
		return types.MCPResourceResult{}, fmt.Errorf("unknown resource %q", uri)
	}
	return m.read(uri)
}

func (m *mockTarget) GetPrompt(_ context.Context, name string, args map[string]string) (types.MCPPromptResult, error) {
	m.promptCalls = append(m.promptCalls, promptCall{name: name, args: args})
	if m.prompt == nil {
		return types.MCPPromptResult{}, fmt.Errorf("unknown prompt %q", name)
	}
	return m.prompt(name, args)
}

// readerOnlyTarget can read primitives but deliberately does NOT implement
// types.MCPReconnaissance, modelling a generator with no catalog available. It is
// declared standalone rather than embedding mockTarget, because embedding would
// promote MCPInventory and satisfy the interface the test needs absent. The probes
// must still work from baseline payloads alone.
type readerOnlyTarget struct {
	read     func(uri string) (types.MCPResourceResult, error)
	readURIs []string
}

func (r *readerOnlyTarget) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (r *readerOnlyTarget) ClearHistory()       {}
func (r *readerOnlyTarget) Name() string        { return "reader-only" }
func (r *readerOnlyTarget) Description() string { return "reader-only" }

func (r *readerOnlyTarget) ReadResource(_ context.Context, uri string) (types.MCPResourceResult, error) {
	r.readURIs = append(r.readURIs, uri)
	if r.read == nil {
		return types.MCPResourceResult{}, fmt.Errorf("unknown resource %q", uri)
	}
	return r.read(uri)
}

func (r *readerOnlyTarget) GetPrompt(_ context.Context, name string, _ map[string]string) (types.MCPPromptResult, error) {
	return types.MCPPromptResult{}, fmt.Errorf("unknown prompt %q", name)
}

// plainTarget is a chat-only generator: no primitive surface at all.
type plainTarget struct{}

func (plainTarget) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (plainTarget) ClearHistory()       {}
func (plainTarget) Name() string        { return "plain" }
func (plainTarget) Description() string { return "plain" }

// passwdBody is the content a real /etc/passwd read returns. Its signature is what
// the detector matches, and it never appears in any payload.
const passwdBody = "root:x:0:0:root:/root:/bin/bash\ndaemon:*:1:1:daemon:/:/usr/bin/false\n"

// arithRE finds a bare multiplication so a fake template engine can evaluate it.
var arithRE = regexp.MustCompile(`(\d+)\s*\*\s*(\d+)`)

// evalArith mimics a server-side template/expression engine: it replaces every
// "N*M" it finds with the product. Applied to a rendered prompt this reproduces
// exactly what an SSTI sink does, across all of the canary's wrapper syntaxes
// ({{...}}, ${...}, $((...)) and so on).
func evalArith(s string) string {
	return arithRE.ReplaceAllStringFunc(s, func(m string) string {
		parts := arithRE.FindStringSubmatch(m)
		a, err1 := strconv.Atoi(parts[1])
		b, err2 := strconv.Atoi(parts[2])
		if err1 != nil || err2 != nil {
			return m
		}
		return strconv.Itoa(a * b)
	})
}

// urlRE extracts the first http(s) URL from a payload. Parentheses are
// deliberately INSIDE the accepted character class: the shell-proof canary splices
// "$()" into the middle of the token, so a class that stopped at "(" would truncate
// the URL and the simulated shell would request an untracked path — the test would
// then pass for the wrong reason (no callback) and hide a real regression.
var urlRE = regexp.MustCompile(`https?://[^\s"'` + "`" + `;|&]+`)

// simulateShell mimics a sink that hands its input to a shell: it extracts the
// canary URL and fetches it, reproducing the two things a POSIX shell does to the
// payload — collapsing the empty command substitution "$()" to nothing, and leaving
// the surrounding command punctuation behind. That collapse is what makes the
// callback proof of command EXECUTION rather than of a plain URL fetch, so a
// simulator that skipped it would never register a hit.
func simulateShell(payload string) {
	raw := urlRE.FindString(payload)
	if raw == "" {
		return
	}
	resolved := strings.ReplaceAll(raw, "$()", "")
	// Trailing punctuation from the wrapping construct — "$(curl URL)", "URL ; #"
	// — is not part of the URL a shell would request.
	resolved = strings.TrimRight(resolved, ")`;|&'\"")
	resp, err := http.Get(resolved) //nolint:gosec,noctx // test-local collector URL
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// fetchURL mimics a sink that resolves a URI as a network location without any
// shell involved — the SSRF shape.
func fetchURL(uri string) string {
	resp, err := http.Get(uri) //nolint:gosec,noctx // test-local collector URL
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(body)
}

// metaString reads a string metadata value from an attempt.
func metaString(t *testing.T, a *attempt.Attempt, key string) string {
	t.Helper()
	raw, ok := a.GetMetadata(key)
	if !ok {
		return ""
	}
	s, _ := raw.(string)
	return s
}

func metaBool(a *attempt.Attempt, key string) bool {
	raw, ok := a.GetMetadata(key)
	if !ok {
		return false
	}
	b, _ := raw.(bool)
	return b
}

func TestExpandTemplate(t *testing.T) {
	tests := []struct {
		name  string
		tpl   string
		value string
		want  string
	}{
		{"simple param", "file:///docs/{path}", "X", "file:///docs/X"},
		{"reserved expansion", "file:///docs/{+path}", "X", "file:///docs/X"},
		{"fragment operator", "https://api/page{#frag}", "X", "https://api/page#X"},
		{"path segment operator", "file:///docs{/path}", "X", "file:///docs/X"},
		{"label operator", "https://api/file{.ext}", "X", "https://api/file.X"},
		{"path-style parameter", "https://api/x{;id}", "X", "https://api/x;id=X"},
		{"query operator", "https://svc/search{?q}", "X", "https://svc/search?q=X"},
		{"query continuation", "https://svc/s?a=1{&b}", "X", "https://svc/s?a=1&b=X"},
		{"multi-variable query", "https://svc/s{?a,b}", "X", "https://svc/s?a=X&b=X"},
		{"explode modifier stripped", "file:///docs/{path*}", "X", "file:///docs/X"},
		{"prefix modifier stripped", "file:///docs/{path:3}", "X", "file:///docs/X"},
		{"two placeholders", "file:///{dir}/{name}", "X", "file:///X/X"},
		{"no placeholder", "file:///docs/fixed.txt", "X", ""},
		{"unterminated placeholder", "file:///docs/{path", "X", "file:///docs/{path"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := expandTemplate(tc.tpl, tc.value); got != tc.want {
				t.Errorf("expandTemplate(%q, %q) = %q, want %q", tc.tpl, tc.value, got, tc.want)
			}
		})
	}
}

func TestTraversalFrom(t *testing.T) {
	got := traversalFrom("file:///data/notes.txt")
	if len(got) == 0 {
		t.Fatal("traversalFrom returned no payloads for a normal resource URI")
	}
	for _, p := range got {
		if !strings.HasPrefix(p.uri, "file:///data/") {
			t.Errorf("payload %q does not preserve the advertised directory prefix", p.uri)
		}
		if len(p.signatures) == 0 {
			t.Errorf("payload %q carries no signatures, so nothing could confirm it", p.uri)
		}
	}

	// Prefix preservation still works wherever there IS a path to preserve.
	for _, uri := range []string{"file:///notes.txt", "https://example.test/d/a.txt"} {
		if got := traversalFrom(uri); len(got) == 0 {
			t.Errorf("traversalFrom(%q) returned nothing; it has a path segment to preserve", uri)
		}
	}

	// A URI with no path segment to replace yields nothing rather than a
	// nonsensical payload. The authority-only cases matter most: the last slash
	// belongs to "://", so the base would be a bare scheme and every payload would
	// come out host-relative (https://../../etc/passwd).
	for _, uri := range []string{
		"opaque",
		"file:///data/",
		"https://example.test",
		"notes://readme",
		"poisoned://onboarding",
	} {
		if got := traversalFrom(uri); got != nil {
			t.Errorf("traversalFrom(%q) = %+v, want nil", uri, got)
		}
	}
}

func TestPromptArgs(t *testing.T) {
	args := []types.MCPPromptArgument{
		{Name: "target", Required: true},
		{Name: "other", Required: true},
		{Name: "optional"},
	}
	got := promptArgs(args, "target", "PAYLOAD")

	if got["target"] != "PAYLOAD" {
		t.Errorf("injected argument = %q, want PAYLOAD", got["target"])
	}
	if got["other"] != "test" {
		t.Errorf("other required argument = %q, want a benign placeholder so the render reaches the sink", got["other"])
	}
	if _, present := got["optional"]; present {
		t.Error("optional argument should be omitted, not filled")
	}
}

// TestBaselinePayloads_TargetDiversity: encoding diversity does not survive a
// server-side filter that keys on the target FILENAME. If every payload named
// passwd, one rule ("reject any URI containing passwd") would defeat the entire
// baseline at once, so the set must span several target files.
func TestBaselinePayloads_TargetDiversity(t *testing.T) {
	base := baselineURIPayloads()

	targets := map[string]bool{}
	for _, p := range base {
		switch {
		case strings.Contains(p.uri, "passwd"):
			targets["passwd"] = true
		case strings.Contains(p.uri, "win.ini"):
			targets["win.ini"] = true
		case strings.Contains(p.uri, "proc/version"):
			targets["proc/version"] = true
		case strings.Contains(p.uri, "os-release"):
			targets["os-release"] = true
		case strings.Contains(p.uri, "hosts"):
			targets["hosts"] = true
		}
		if len(p.signatures) == 0 {
			t.Errorf("payload %q carries no signature, so nothing could confirm it", p.uri)
		}
	}
	if len(targets) < 4 {
		t.Errorf("baseline spans only %d target files (%v); a single filename filter would defeat too much of it", len(targets), targets)
	}

	// No single filename filter may remove everything.
	for _, filter := range []string{"passwd", "win.ini", "proc", "os-release", "hosts"} {
		surviving := 0
		for _, p := range base {
			if !strings.Contains(p.uri, filter) {
				surviving++
			}
		}
		if surviving == 0 {
			t.Errorf("filtering %q defeats every baseline payload", filter)
		}
	}
}

// TestSignatures_NoLowEntropyMarkers guards the precision of the oracle: a
// signature short or generic enough to occur in ordinary served content turns a
// confirmed read into a guess. Bare "ID=" and "127.0.0.1 localhost" are the two
// tempting-but-wrong markers for the files added here.
func TestSignatures_NoLowEntropyMarkers(t *testing.T) {
	// Six characters is the floor rather than a longer bound because structural
	// markers can be short yet highly specific: "[fonts]" is a win.ini section
	// header and will not appear in prose, whereas a three-character "ID=" will.
	const minSignature = 6

	all := [][]string{passwdSignatures, winIniSignatures, procVersionSignatures, osReleaseSignatures, hostsSignatures}
	for _, set := range all {
		for _, sig := range set {
			if len(sig) < minSignature {
				t.Errorf("signature %q is short enough to collide with benign content", sig)
			}
			if sig == "ID=" || strings.Contains(sig, "127.0.0.1 localhost") {
				t.Errorf("signature %q occurs in ordinary documentation", sig)
			}
		}
	}
}
