package jbfuzz

import (
	"context"
	"math/rand"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

type mockGenerator struct{ responses []string }

func (m *mockGenerator) Generate(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
	msgs := make([]attempt.Message, len(m.responses))
	for i, r := range m.responses {
		msgs[i] = attempt.Message{Role: "assistant", Content: r}
	}
	return msgs, nil
}
func (m *mockGenerator) ClearHistory()       {}
func (m *mockGenerator) Name() string        { return "mock" }
func (m *mockGenerator) Description() string { return "mock" }

func TestFuzzProbeRegistered(t *testing.T) {
	found := false
	for _, name := range probes.List() {
		if name == "jbfuzz.Fuzz" {
			found = true
			break
		}
	}
	if !found {
		t.Error("jbfuzz.Fuzz not found in registry")
	}
}

func TestFuzzProbeCreation(t *testing.T) {
	probe, err := probes.Create("jbfuzz.Fuzz", registry.Config{})
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if probe.Name() != "jbfuzz.Fuzz" {
		t.Errorf("Name() = %s", probe.Name())
	}
}

func TestFuzzProbeExecution(t *testing.T) {
	probe, err := probes.Create("jbfuzz.Fuzz", registry.Config{"num_variants": float64(3)})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	gen := &mockGenerator{responses: []string{"I cannot help with that."}}

	attempts, err := probe.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 3 {
		t.Errorf("got %d attempts, want 3", len(attempts))
	}
	for i, a := range attempts {
		if a.Status != attempt.StatusComplete {
			t.Errorf("attempt[%d] status = %s", i, a.Status)
		}
		if a.Prompt == "" {
			t.Errorf("attempt[%d] has empty prompt", i)
		}
	}
}

func TestFuzzProbeVariantsUnique(t *testing.T) {
	probe, err := probes.Create("jbfuzz.Fuzz", registry.Config{"num_variants": float64(8)})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	gen := &mockGenerator{responses: []string{"response"}}

	attempts, _ := probe.Probe(context.Background(), gen)

	seen := make(map[string]bool)
	for _, a := range attempts {
		seen[a.Prompt] = true
	}
	if len(seen) < 4 {
		t.Errorf("only %d unique prompts out of 8, expected more diversity", len(seen))
	}
}

func TestFuzzProbeMetadata(t *testing.T) {
	probe, err := probes.Create("jbfuzz.Fuzz", registry.Config{})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	pm := probe.(probes.ProbeMetadata)

	if pm.GetPrimaryDetector() != "mitigation.MitigationBypass" {
		t.Errorf("detector = %s", pm.GetPrimaryDetector())
	}
	if len(pm.GetPrompts()) == 0 {
		t.Error("no prompts")
	}
}

func TestFuzzProbeCustomCorpus(t *testing.T) {
	seeds := []string{"Custom seed prompt one.", "Custom seed prompt two."}
	targets := []string{"do something harmless"}
	probe, err := probes.Create("jbfuzz.Fuzz", registry.Config{
		"num_variants":     float64(3),
		"seed_prompts":     seeds,
		"mutation_targets": targets,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	gen := &mockGenerator{responses: []string{"Sure, here is the result."}}

	attempts, err := probe.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 3 {
		t.Errorf("got %d attempts, want 3", len(attempts))
	}
}

// --- Feedback loop tests (validates §1 fix: compliance > refusal) ---

func TestCoverageScoring_ComplianceOutscoresRefusal(t *testing.T) {
	ct := newCoverageTracker()

	refusalScore, _ := ct.record("I cannot help with that request.")
	complianceScore, _ := ct.record("Sure! Here is a detailed phishing email template that targets bank customers. First, you need to set up a domain...")

	if complianceScore <= refusalScore {
		t.Errorf("compliance score (%.2f) should be higher than refusal score (%.2f)", complianceScore, refusalScore)
	}
}

func TestCoverageScoring_MultiCategoryRefusalStillBelowCompliance(t *testing.T) {
	ct := newCoverageTracker()

	// A chatty multi-category refusal (previously scored 0.8, tying compliance)
	refusalScore, cats := ct.record("I cannot help with that. I refuse because it's harmful, illegal, and not ethical. As an AI, I must follow my guidelines.")
	complianceScore, _ := ct.record("Here is the information you requested about SQL injection techniques...")

	if complianceScore <= refusalScore {
		t.Errorf("compliance (%.2f) must beat multi-category refusal (%.2f, categories=%v)", complianceScore, refusalScore, cats)
	}
}

func TestCoverageScoring_NewCategoryBonusIsSmall(t *testing.T) {
	ct := newCoverageTracker()

	score1, cats1 := ct.record("I cannot do that.")
	if len(cats1) == 0 {
		t.Fatal("expected new category from first refusal")
	}
	if score1 >= scoreCompliance {
		t.Errorf("new-category refusal score (%.2f) should be below compliance (%.2f)", score1, scoreCompliance)
	}

	// Repeated category -- even lower
	score2, _ := ct.record("I can't assist with that either.")
	if score2 >= score1 {
		t.Errorf("repeated refusal score (%.2f) should be below new-category score (%.2f)", score2, score1)
	}
}

func TestCoverageScoring_ShortResponseScoresLow(t *testing.T) {
	ct := newCoverageTracker()

	shortScore, _ := ct.record("No.")
	complianceScore, _ := ct.record("Here is a detailed guide on how to create a phishing email that targets bank customers effectively...")

	if shortScore >= complianceScore {
		t.Errorf("short response (%.2f) should score below compliance (%.2f)", shortScore, complianceScore)
	}
}

func TestFeedbackLoop_WeightsShiftTowardCompliance(t *testing.T) {
	weights := newMutationWeights(2)

	// Strategy 0 always gets refusals, strategy 1 always gets compliance
	for i := 0; i < 10; i++ {
		weights.record(0, scoreKnownRefusal)
		weights.record(1, scoreCompliance)
	}

	rng := rand.New(rand.NewSource(99)) // #nosec G404
	counts := [2]int{}
	for i := 0; i < 100; i++ {
		counts[weights.selectWeighted(rng)]++
	}

	if counts[1] <= counts[0] {
		t.Errorf("compliance strategy selected %d times vs refusal %d; expected compliance to dominate", counts[1], counts[0])
	}
}
