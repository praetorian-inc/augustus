package mcpprimitive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"testing"

	mcpx "github.com/praetorian-inc/augustus/internal/recon/mcp"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/output"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// Regression tests for the review findings on this branch.

// readerOnlyTarget (declared in mcpprimitive_test.go) implements
// MCPPrimitiveReader but deliberately NOT MCPReconnaissance — exactly the shape
// that previously produced a silent, successful, empty scan.
//
// TestContentLeak_CannotEnumerateIsAnError covers a false-clean path. Every surface
// this probe reads is discoverable only from the catalog, so a target whose catalog
// cannot be enumerated cannot be assessed. Previously resolveInventories returned
// (nil, nil) for such a target, all three surface groups produced nothing, and the
// probe returned no attempts and no error — output byte-identical to a target that
// genuinely advertises nothing.
//
// "We could not ask" and "there was nothing there" must not look the same.
func TestContentLeak_CannotEnumerateIsAnError(t *testing.T) {
	_, err := newContentLeakProbe(t, nil).Probe(context.Background(), &readerOnlyTarget{})
	if err == nil {
		t.Fatal("Probe returned no error for a target whose catalog cannot be enumerated; an unassessable surface must not read as a clean pass")
	}
	// The paired positive lives in the existing suite: a recon-capable target with
	// an empty catalog still returns no attempts and no error, because there the
	// emptiness is an answer rather than an inability to ask.
}

// TestContentLeak_TransportFailureIsNotARefusal covers the most consequential
// misclassification on this branch. resources/read and prompts/get have no
// application-level error flag, so a server's REFUSAL can only arrive as a Go
// error — which the probe correctly treats as a non-finding. But it applied that
// rule to every error, so a deadline, a cancelled scan or a dead connection also
// completed as a clean non-finding.
//
// That matters most exactly where such errors cluster: a small or busy target
// dropping requests, which is when a green result is least trustworthy.
func TestContentLeak_TransportFailureIsNotARefusal(t *testing.T) {
	transport := []struct {
		name string
		err  error
	}{
		{"deadline", context.DeadlineExceeded},
		{"cancelled", context.Canceled},
		{"net timeout", &net.OpError{Op: "read", Err: timeoutErr{}}},
		{"connection refused", errors.New("dial tcp 127.0.0.1:8000: connect: connection refused")},
		{"wrapped deadline", fmt.Errorf("reading resource: %w", context.DeadlineExceeded)},
	}
	for _, tc := range transport {
		t.Run(tc.name, func(t *testing.T) {
			target := &mockTarget{
				inv:  &types.MCPInventory{Resources: []types.MCPResource{{URI: "file:///secret"}}},
				read: func(string) (types.MCPResourceResult, error) { return types.MCPResourceResult{}, tc.err },
			}
			attempts, err := newContentLeakProbe(t, nil).Probe(context.Background(), target)
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if len(attempts) != 1 {
				t.Fatalf("got %d attempts, want 1", len(attempts))
			}
			a := attempts[0]
			if a.Status != attempt.StatusError {
				t.Errorf("status = %q, want %q; a surface we never reached was not assessed", a.Status, attempt.StatusError)
			}
			if v, _ := a.Metadata[attempt.MetadataKeyInconclusive].(bool); !v {
				t.Error("attempt not marked inconclusive; a failure to communicate must stay visible")
			}
			if a.Metadata[attempt.MetadataKeyInconclusiveReason] == "" {
				t.Error("no inconclusive reason recorded; a reviewer must be told what to re-check")
			}
		})
	}
}

// storeWithInventory builds a recon store holding one inventory observation, the
// same shape recon.MCP emits.
func storeWithInventory(t *testing.T, inv *types.MCPInventory) *recon.Store {
	t.Helper()
	data, err := json.Marshal(inv)
	if err != nil {
		t.Fatalf("marshal inventory: %v", err)
	}
	store := recon.NewStore()
	store.Observe(output.Observation{Type: mcpx.ObservationTypeInventory, Data: data})
	return store
}

// timeoutErr is a net.Error whose Timeout() is true.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// TestContentLeak_ApplicationRefusalStaysANonFinding is the paired negative: the
// denial contract must survive the fix. An application-level refusal means the
// surface WAS reached and access was denied, which is a completed non-finding.
func TestContentLeak_ApplicationRefusalStaysANonFinding(t *testing.T) {
	target := &mockTarget{
		inv: &types.MCPInventory{Resources: []types.MCPResource{{URI: "file:///secret"}}},
		read: func(string) (types.MCPResourceResult, error) {
			return types.MCPResourceResult{}, errors.New("access denied: resource requires authorization")
		},
	}
	attempts, err := newContentLeakProbe(t, nil).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("got %d attempts, want 1", len(attempts))
	}
	a := attempts[0]
	if a.Status != attempt.StatusComplete {
		t.Errorf("status = %q, want %q; a refusal is an answer, not a probe failure", a.Status, attempt.StatusComplete)
	}
	if v, _ := a.Metadata[attempt.MetadataKeyInconclusive].(bool); v {
		t.Error("refusal marked inconclusive; the denial contract was lost")
	}
	if a.Metadata[attempt.MetadataKeyPrimitiveCallError] == "" {
		t.Error("refusal not preserved in metadata")
	}
}

// TestNewContentLeak_RejectsNonPositiveCap covers a misconfiguration that produced
// a scan indistinguishable from a clean one: a zero cap satisfies the per-group
// budget check immediately, so every surface is skipped and no attempt is emitted.
func TestNewContentLeak_RejectsNonPositiveCap(t *testing.T) {
	for _, v := range []int{0, -1} {
		if _, err := NewContentLeak(registry.Config{"content_max_targets": v}); err == nil {
			t.Errorf("content_max_targets=%d accepted; a non-positive cap silently skips every surface", v)
		}
	}
	if _, err := NewContentLeak(registry.Config{"content_max_targets": 1}); err != nil {
		t.Errorf("content_max_targets=1 rejected: %v", err)
	}
}

// TestResolveInventories_RetriesIncompleteStoredInventory covers the reuse
// asymmetry CodeRabbit flagged. A stored inventory whose enumeration stopped early
// is a snapshot of one earlier walk; a fresh walk may simply succeed, and reusing
// the partial one silently narrows every surface downstream.
//
// Note what is deliberately NOT done: when the live walk is also incomplete the
// stored inventory is used anyway rather than discarded. The sibling tool-surface
// probes refuse a truncated catalog because they emit nothing when it is short, so
// scoring a prefix would report a clean no-op. These probes report what they FIND
// and never certify absence, so scoring a prefix still surfaces real findings in
// it — refusing would discard them to avoid an overclaim never made.
func TestResolveInventories_RetriesIncompleteStoredInventory(t *testing.T) {
	complete := &types.MCPInventory{Resources: []types.MCPResource{{URI: "file:///fresh"}}}
	target := &mockTarget{inv: complete}

	// A live walk happens because the stored inventory is incomplete.
	partial := &types.MCPInventory{
		Resources:  []types.MCPResource{{URI: "file:///stale"}},
		Incomplete: []string{string(types.MCPCatalogResources)},
	}
	r := &reconContext{store: storeWithInventory(t, partial)}
	got, err := r.resolveInventories(context.Background(), target)
	if err != nil {
		t.Fatalf("resolveInventories: %v", err)
	}
	if len(got) != 1 || len(got[0].Resources) == 0 || got[0].Resources[0].URI != "file:///fresh" {
		t.Errorf("incomplete stored inventory was reused instead of retried live; got %+v", got)
	}

	// A COMPLETE stored inventory is reused with no live call, which is the whole
	// point of "scan once, reuse everywhere".
	target2 := &mockTarget{invErr: errors.New("live enumeration must not be attempted")}
	r2 := &reconContext{store: storeWithInventory(t, complete)}
	if _, err := r2.resolveInventories(context.Background(), target2); err != nil {
		t.Errorf("complete stored inventory triggered a live walk: %v", err)
	}
}
