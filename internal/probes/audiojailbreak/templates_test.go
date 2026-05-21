package audiojailbreak

import (
	"testing"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestProbeCreation(t *testing.T) {
	for _, name := range probes.List() {
		if len(name) > len("audiojailbreak.") && name[:len("audiojailbreak.")] == "audiojailbreak." {
			t.Run(name, func(t *testing.T) {
				probe, err := probes.Create(name, registry.Config{})
				if err != nil {
					t.Fatalf("error = %v", err)
				}
				if probe.Name() != name {
					t.Errorf("Name() = %s, want %s", probe.Name(), name)
				}
				pm := probe.(probes.ProbeMetadata)
				if len(pm.GetPrompts()) == 0 {
					t.Error("no prompts")
				}
			})
		}
	}
}
