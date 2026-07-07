package toolsec

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func newReconDetector(t *testing.T) *ReconDetector {
	t.Helper()
	d, err := NewReconDetector(registry.Config{})
	if err != nil {
		t.Fatalf("NewReconDetector: %v", err)
	}
	return d.(*ReconDetector)
}

func TestReconDetector_FlagsWhenSuspicious(t *testing.T) {
	d := newReconDetector(t)
	a := attempt.New("recon")
	a.AddOutput("summary")
	a.Metadata[attempt.MetadataKeyMCPSuspiciousFlags] = []types.MCPSuspiciousFlag{
		{Category: types.MCPFlagImperativeInjection, Tool: "read_notes", Location: "description"},
	}

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(scores) != 1 || scores[0] != 1.0 {
		t.Fatalf("expected [1.0], got %v", scores)
	}
}

func TestReconDetector_CleanScoresZero(t *testing.T) {
	d := newReconDetector(t)
	a := attempt.New("recon")
	a.AddOutput("summary")
	a.Metadata[attempt.MetadataKeyMCPSuspiciousFlags] = []types.MCPSuspiciousFlag{}

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(scores) != 1 || scores[0] != 0.0 {
		t.Fatalf("expected [0.0], got %v", scores)
	}
}

func TestReconDetector_NoMetadataScoresZero(t *testing.T) {
	d := newReconDetector(t)
	a := attempt.New("recon")
	a.AddOutput("summary")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(scores) != 1 || scores[0] != 0.0 {
		t.Fatalf("expected [0.0], got %v", scores)
	}
}

// TestReconDetector_ToleratesJSONRoundTrip: metadata that has passed through
// JSON (flags become []any) must still be counted.
func TestReconDetector_ToleratesJSONRoundTrip(t *testing.T) {
	d := newReconDetector(t)
	a := attempt.New("recon")
	a.AddOutput("summary")

	flags := []types.MCPSuspiciousFlag{{Category: types.MCPFlagEmbeddedURL, Tool: "x", Location: "description"}}
	blob, err := json.Marshal(flags)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundTripped []any
	if err := json.Unmarshal(blob, &roundTripped); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	a.Metadata[attempt.MetadataKeyMCPSuspiciousFlags] = roundTripped

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(scores) != 1 || scores[0] != 1.0 {
		t.Fatalf("expected [1.0] after round-trip, got %v", scores)
	}
}
