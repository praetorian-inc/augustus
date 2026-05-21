package lrmagent

import (
	"testing"
	"github.com/praetorian-inc/augustus/pkg/probes"
)

func TestLRMRegistered(t *testing.T) {
	found := false
	for _, name := range probes.List() {
		if name == "lrmagent.LRM" {
			found = true
			break
		}
	}
	if !found {
		t.Error("lrmagent.LRM not found in registry")
	}
}
