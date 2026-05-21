package memoryinject

import (
	"context"
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

func TestMINJARegistered(t *testing.T) {
	found := false
	for _, name := range probes.List() {
		if name == "memoryinject.MINJA" {
			found = true
			break
		}
	}
	if !found {
		t.Error("memoryinject.MINJA not found in registry")
	}
}

func TestPersistentInjectionRegistered(t *testing.T) {
	found := false
	for _, name := range probes.List() {
		if name == "memoryinject.PersistentInjection" {
			found = true
			break
		}
	}
	if !found {
		t.Error("memoryinject.PersistentInjection not found in registry")
	}
}

func TestMINJAExecution(t *testing.T) {
	probe, err := probes.Create("memoryinject.MINJA", registry.Config{})
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	gen := &mockGenerator{responses: []string{"I cannot store that."}}
	attempts, err := probe.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("no attempts")
	}
}
