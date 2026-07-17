package mcpconfig

import (
	"context"
	"testing"

	mcpconfigrecon "github.com/praetorian-inc/augustus/internal/recon/mcpconfig"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"

	// Register the mcpsecrets.Credential detector for the end-to-end assertions.
	_ "github.com/praetorian-inc/augustus/internal/detectors/mcpsecrets"
)

func newProbe(t *testing.T) *CredentialExposure {
	t.Helper()
	p, err := NewCredentialExposure(registry.Config{})
	if err != nil {
		t.Fatalf("NewCredentialExposure() error = %v", err)
	}
	cp, ok := p.(*CredentialExposure)
	if !ok {
		t.Fatalf("NewCredentialExposure() returned %T, want *CredentialExposure", p)
	}
	return cp
}

// storeWithConfig runs the recon.MCPConfig module over inline content and returns
// a store populated with the resulting config observations, mirroring the runtime
// recon-then-probe flow.
func storeWithConfig(t *testing.T, content string) *recon.Store {
	t.Helper()
	m, err := mcpconfigrecon.New(registry.Config{"content": content})
	if err != nil {
		t.Fatalf("recon New: %v", err)
	}
	obs, err := m.Recon(context.Background(), nil)
	if err != nil {
		t.Fatalf("recon Recon: %v", err)
	}
	store := recon.NewStore()
	for _, o := range obs {
		store.Observe(o)
	}
	return store
}

// score runs the real mcpsecrets.Credential detector over an attempt's outputs.
func score(t *testing.T, a *attempt.Attempt) []float64 {
	t.Helper()
	det, err := detectors.Create("mcpsecrets.Credential", registry.Config{})
	if err != nil {
		t.Fatalf("detectors.Create: %v", err)
	}
	scores, err := det.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	return scores
}

func TestCredentialExposure_Metadata(t *testing.T) {
	p := newProbe(t)
	if p.Name() != "mcpconfig.CredentialExposure" {
		t.Errorf("Name() = %q, want %q", p.Name(), "mcpconfig.CredentialExposure")
	}
	if p.GetPrimaryDetector() != "mcpsecrets.Credential" {
		t.Errorf("GetPrimaryDetector() = %q, want %q", p.GetPrimaryDetector(), "mcpsecrets.Credential")
	}
	if p.Description() == "" {
		t.Error("Description() is empty")
	}
	if p.Goal() == "" {
		t.Error("Goal() is empty")
	}
	if p.GetPrompts() != nil {
		t.Errorf("GetPrompts() = %v, want nil", p.GetPrompts())
	}
}

func TestCredentialExposure_LeakyConfigScoresVulnerable(t *testing.T) {
	p := newProbe(t)
	p.SetContext(recon.ProbeContext{
		Recon: storeWithConfig(t, `{"env":{"GITHUB_TOKEN":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}}`),
	})

	attempts, err := p.Probe(context.Background(), nil)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("got %d attempts, want 1", len(attempts))
	}
	a := attempts[0]
	if a.Probe != "mcpconfig.CredentialExposure" {
		t.Errorf("attempt.Probe = %q", a.Probe)
	}
	if a.Detector != "mcpsecrets.Credential" {
		t.Errorf("attempt.Detector = %q", a.Detector)
	}
	if src, _ := a.GetMetadata("source"); src != "inline" {
		t.Errorf("metadata source = %v, want inline", src)
	}
	scores := score(t, a)
	if len(scores) != 1 || scores[0] != 1.0 {
		t.Errorf("scores = %v, want [1.0] (leaky config)", scores)
	}
}

func TestCredentialExposure_CleanConfigScoresSafe(t *testing.T) {
	p := newProbe(t)
	p.SetContext(recon.ProbeContext{
		Recon: storeWithConfig(t, `{"env":{"LOG_LEVEL":"debug","TIMEOUT":"30"}}`),
	})

	attempts, err := p.Probe(context.Background(), nil)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("got %d attempts, want 1", len(attempts))
	}
	scores := score(t, attempts[0])
	if len(scores) != 1 || scores[0] != 0.0 {
		t.Errorf("scores = %v, want [0.0] (clean config)", scores)
	}
}

func TestCredentialExposure_EmptyStoreYieldsInformationalAttempt(t *testing.T) {
	p := newProbe(t)
	p.SetContext(recon.ProbeContext{Recon: recon.NewStore()})

	attempts, err := p.Probe(context.Background(), nil)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("got %d attempts, want 1 informational", len(attempts))
	}
	a := attempts[0]
	if a.Error != "" {
		t.Errorf("informational attempt has error %q, want none", a.Error)
	}
	// The informational attempt must be benign: the detector must not flag it.
	scores := score(t, a)
	for i, s := range scores {
		if s != 0.0 {
			t.Errorf("informational score[%d] = %v, want 0.0", i, s)
		}
	}
}

func TestCredentialExposure_NilStoreYieldsInformationalAttempt(t *testing.T) {
	p := newProbe(t)
	// No SetContext called: store is nil (recon was not run).
	attempts, err := p.Probe(context.Background(), nil)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("got %d attempts, want 1 informational", len(attempts))
	}
}
