package killchain

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
)

func TestKillChainRegistered(t *testing.T) {
	found := false
	for _, name := range probes.List() {
		if name == "killchain.KillChain" {
			found = true
			break
		}
	}
	if !found {
		t.Error("killchain.KillChain not found in registry")
	}
}

// Full execution test requires attacker + judge LLMs configured.
// Registration test verifies the probe factory and strategy compile correctly.
