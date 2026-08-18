package mcpprobe

import (
	"io"
	"net/http"
	"testing"
)

func get(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url) //nolint:noctx,gosec // test-local collector
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

// TestCollector_RecordsOnlyIssuedTokens: the collector is reachable from the target
// on any remote scan, so anyone can request /oob/<anything>. Recording every token
// seen would grow the map without bound and log callbacks the probe never asked
// for, so only tokens actually handed out by URL() are tracked.
func TestCollector_RecordsOnlyIssuedTokens(t *testing.T) {
	c, err := StartCollector("127.0.0.1:0", "", "MARKER")
	if err != nil {
		t.Fatalf("StartCollector: %v", err)
	}
	defer c.Close()

	issued := c.URL("issued-token")

	// An unissued token: fetched, answered, but never recorded.
	if body := get(t, c.base+"/oob/never-issued"); body != "MARKER" {
		t.Errorf("body = %q, want the marker — an unknown caller must still get a reply", body)
	}
	if c.WasHit("never-issued") {
		t.Error("collector recorded a token it never issued")
	}
	c.mu.Lock()
	tracked := len(c.hits)
	c.mu.Unlock()
	if tracked != 0 {
		t.Errorf("hits map holds %d entries after an unissued callback, want 0 (unbounded growth)", tracked)
	}

	// The issued token is recorded as normal.
	if body := get(t, issued); body != "MARKER" {
		t.Errorf("body = %q, want the marker", body)
	}
	if !c.WasHit("issued-token") {
		t.Error("collector did not record a callback for a token it issued")
	}
}

// TestCollector_ShellProofReplayIsIgnored: a sink that fetches the literal
// "…$()…" path instead of executing it requests a token that was never issued, so
// it must not be recorded. Only a real shell collapses $() back to the tracked
// token, which is what makes the callback proof of command execution.
func TestCollector_ShellProofReplayIsIgnored(t *testing.T) {
	c, err := StartCollector("127.0.0.1:0", "", "MARKER")
	if err != nil {
		t.Fatalf("StartCollector: %v", err)
	}
	defer c.Close()

	token := "abcdef0123456789"
	proof := ShellProofURL(c.URL(token), token)

	get(t, proof) // literal fetch, no shell — the $() is still in the path
	if c.WasHit(token) {
		t.Error("a literal (non-shell) fetch was recorded as a command-execution callback")
	}

	get(t, c.URL(token)) // what a real shell would request
	if !c.WasHit(token) {
		t.Error("the collapsed path was not recorded")
	}
}
