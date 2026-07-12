package mcpconfig

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	// Register the mcpsecrets detector so the end-to-end test can resolve it.
	_ "github.com/praetorian-inc/augustus/internal/detectors/mcpsecrets"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

const leakyConfig = `{"mcpServers":{"gh":{"command":"srv","env":{"GITHUB_TOKEN":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}}}}`

const cleanConfig = `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/data"],"env":{"API_KEY":"${FS_API_KEY}"}}}}`

func newProbe(t *testing.T, cfg registry.Config) *SecretScan {
	t.Helper()
	p, err := NewSecretScan(cfg)
	if err != nil {
		t.Fatalf("NewSecretScan() error = %v", err)
	}
	sp, ok := p.(*SecretScan)
	if !ok {
		t.Fatalf("NewSecretScan() returned %T, want *SecretScan", p)
	}
	return sp
}

func TestSecretScan_Metadata(t *testing.T) {
	p := newProbe(t, registry.Config{"content": leakyConfig})
	if p.Name() != "mcpconfig.SecretScan" {
		t.Errorf("Name() = %q, want %q", p.Name(), "mcpconfig.SecretScan")
	}
	if p.GetPrimaryDetector() != "mcpsecrets.ConfigLeak" {
		t.Errorf("GetPrimaryDetector() = %q, want %q", p.GetPrimaryDetector(), "mcpsecrets.ConfigLeak")
	}
	if p.Description() == "" || p.Goal() == "" {
		t.Error("Description()/Goal() must be non-empty")
	}
}

func TestSecretScan_InlineContent(t *testing.T) {
	p := newProbe(t, registry.Config{"content": leakyConfig})
	attempts, err := p.Probe(context.Background(), nil)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("got %d attempts, want 1", len(attempts))
	}
	a := attempts[0]
	if a.Probe != "mcpconfig.SecretScan" {
		t.Errorf("attempt.Probe = %q", a.Probe)
	}
	if a.Detector != "mcpsecrets.ConfigLeak" {
		t.Errorf("attempt.Detector = %q", a.Detector)
	}
	if a.Status != attempt.StatusComplete {
		t.Errorf("attempt.Status = %q, want complete", a.Status)
	}
	if len(a.Outputs) != 1 || a.Outputs[0] != leakyConfig {
		t.Errorf("attempt.Outputs = %v, want [leakyConfig]", a.Outputs)
	}
}

func TestSecretScan_EndToEnd_DetectorFlagsLeak(t *testing.T) {
	p := newProbe(t, registry.Config{"content": leakyConfig})
	attempts, err := p.Probe(context.Background(), nil)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}

	det, err := detectors.Create("mcpsecrets.ConfigLeak", registry.Config{})
	if err != nil {
		t.Fatalf("resolve detector: %v", err)
	}
	scores, err := det.Detect(context.Background(), attempts[0])
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(scores) != 1 || scores[0] != 1.0 {
		t.Errorf("scores = %v, want [1.0]", scores)
	}
}

func TestSecretScan_EndToEnd_CleanConfigPasses(t *testing.T) {
	p := newProbe(t, registry.Config{"content": cleanConfig})
	attempts, _ := p.Probe(context.Background(), nil)
	det, _ := detectors.Create("mcpsecrets.ConfigLeak", registry.Config{})
	scores, _ := det.Detect(context.Background(), attempts[0])
	if len(scores) != 1 || scores[0] != 0.0 {
		t.Errorf("scores = %v, want [0.0]", scores)
	}
}

func TestSecretScan_SingleFile(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(fp, []byte(leakyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	p := newProbe(t, registry.Config{"path": fp})
	attempts, err := p.Probe(context.Background(), nil)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("got %d attempts, want 1", len(attempts))
	}
	if src, _ := attempts[0].GetMetadata("source"); src != fp {
		t.Errorf("attempt source metadata = %v, want %q", src, fp)
	}
}

func TestSecretScan_Directory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(leakyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A non-config file that should be ignored.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("no secrets here"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := newProbe(t, registry.Config{"path": dir})
	attempts, err := p.Probe(context.Background(), nil)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 2 {
		t.Fatalf("got %d attempts, want 2 (json + .env, README ignored)", len(attempts))
	}
}

func TestSecretScan_NestedSubdirectoryIsWalked(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "sub", "dir")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	fp := filepath.Join(nested, "mcp.json")
	if err := os.WriteFile(fp, []byte(leakyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	p := newProbe(t, registry.Config{"path": dir})
	attempts, err := p.Probe(context.Background(), nil)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("got %d attempts, want 1 (nested mcp.json)", len(attempts))
	}
	if src, _ := attempts[0].GetMetadata("source"); src != fp {
		t.Errorf("attempt source metadata = %v, want %q", src, fp)
	}
}

func TestSecretScan_PathAndContentBothScanned(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(fp, []byte(leakyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	p := newProbe(t, registry.Config{"path": fp, "content": cleanConfig})
	attempts, err := p.Probe(context.Background(), nil)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 2 {
		t.Fatalf("got %d attempts, want 2 (inline + file)", len(attempts))
	}
	labels := map[string]bool{}
	for _, a := range attempts {
		if src, ok := a.GetMetadata("source"); ok {
			labels[src.(string)] = true
		}
	}
	if !labels["inline"] {
		t.Errorf("missing inline source, got sources %v", labels)
	}
	if !labels[fp] {
		t.Errorf("missing file source %q, got sources %v", fp, labels)
	}
}

func TestSecretScan_ContextCancellationReturnsError(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(fp, []byte(leakyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	// Two sources: inline content plus a file.
	p := newProbe(t, registry.Config{"path": fp, "content": cleanConfig})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before calling Probe

	_, err := p.Probe(ctx, nil)
	if err == nil {
		t.Fatal("Probe() with cancelled context returned nil error, want ctx.Err()")
	}
	if err != context.Canceled {
		t.Errorf("Probe() error = %v, want %v", err, context.Canceled)
	}
}

func TestSecretScan_LargeFileSkippedWithError(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "big.json")
	if err := os.WriteFile(fp, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Grow the file beyond maxFileSize without buffering real content.
	if err := os.Truncate(fp, maxFileSize+1); err != nil {
		t.Fatal(err)
	}
	p := newProbe(t, registry.Config{"path": fp})
	attempts, err := p.Probe(context.Background(), nil)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("got %d attempts, want 1", len(attempts))
	}
	if attempts[0].Status != attempt.StatusError {
		t.Errorf("attempt.Status = %q, want error for oversize file", attempts[0].Status)
	}
}

func TestSecretScan_NoSourceProducesError(t *testing.T) {
	p := newProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), nil)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 1 || attempts[0].Status != attempt.StatusError {
		t.Fatalf("want single error attempt, got %+v", attempts)
	}
}

func TestSecretScan_MissingPathProducesError(t *testing.T) {
	p := newProbe(t, registry.Config{"path": "/nonexistent/path/mcp.json"})
	attempts, err := p.Probe(context.Background(), nil)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 1 || attempts[0].Status != attempt.StatusError {
		t.Fatalf("want single error attempt, got %+v", attempts)
	}
}
