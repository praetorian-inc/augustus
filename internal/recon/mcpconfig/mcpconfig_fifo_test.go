//go:build unix

package mcpconfig

import (
	"context"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/output"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// TestModule_SkipsNonRegularFiles: review finding F — a non-regular file (here a
// FIFO named like a config file) must be skipped, not opened: os.ReadFile on a
// FIFO with no writer blocks indefinitely. Regular files in the same directory
// are still collected. The Recon call is run under a timeout so the pre-fix
// blocking read manifests as a clean test failure rather than an infinite hang.
func TestModule_SkipsNonRegularFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "ok.json", `{"env":{"OK":"value"}}`)

	fifo := filepath.Join(dir, "config.env")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported on this platform: %v", err)
	}

	m := newModule(t, registry.Config{"path": dir})

	type result struct {
		obs []output.Observation
		err error
	}
	done := make(chan result, 1)
	go func() {
		obs, err := m.Recon(context.Background(), nil)
		done <- result{obs, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Recon() error = %v", r.err)
		}
		if len(r.obs) != 1 {
			t.Fatalf("got %d observations, want 1 (FIFO skipped, regular file collected)", len(r.obs))
		}
		if filepath.Base(r.obs[0].Target) != "ok.json" {
			t.Errorf("Target = %q, want ok.json", r.obs[0].Target)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Recon() blocked reading a non-regular file (FIFO); it must skip non-regular files")
	}
}
