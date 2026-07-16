package mcpconfig

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/output"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func newModule(t *testing.T, cfg registry.Config) *Module {
	t.Helper()
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	mod, ok := m.(*Module)
	if !ok {
		t.Fatalf("New() returned %T, want *Module", m)
	}
	return mod
}

// decodeContent extracts the JSON-encoded file content carried by an observation.
func decodeContent(t *testing.T, o output.Observation) string {
	t.Helper()
	var content string
	if err := json.Unmarshal(o.Data, &content); err != nil {
		t.Fatalf("decode observation data: %v", err)
	}
	return content
}

func TestModule_Name(t *testing.T) {
	m := newModule(t, registry.Config{})
	if m.Name() != "recon.MCPConfig" {
		t.Errorf("Name() = %q, want %q", m.Name(), "recon.MCPConfig")
	}
}

func TestModule_InlineContent(t *testing.T) {
	m := newModule(t, registry.Config{"content": `{"env":{"API_KEY":"secret"}}`})
	obs, err := m.Recon(context.Background(), nil)
	if err != nil {
		t.Fatalf("Recon() error = %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1", len(obs))
	}
	o := obs[0]
	if o.Type != ObservationTypeConfig {
		t.Errorf("Type = %q, want %q", o.Type, ObservationTypeConfig)
	}
	if o.Target != "inline" {
		t.Errorf("Target = %q, want %q", o.Target, "inline")
	}
	if o.Source != "recon.MCPConfig" {
		t.Errorf("Source = %q, want %q", o.Source, "recon.MCPConfig")
	}
	if got := decodeContent(t, o); got != `{"env":{"API_KEY":"secret"}}` {
		t.Errorf("content = %q, want inline content", got)
	}
}

func TestModule_DirectoryScansConfigFilesOnly(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.json", `{"a":1}`)
	writeFile(t, dir, "secrets.env", `API_KEY=abc`)
	writeFile(t, dir, "UPPER.JSON", `{"b":2}`) // uppercase extension is still scanned
	writeFile(t, dir, "README.md", `# ignore me`)

	m := newModule(t, registry.Config{"path": dir})
	obs, err := m.Recon(context.Background(), nil)
	if err != nil {
		t.Fatalf("Recon() error = %v", err)
	}
	if len(obs) != 3 {
		t.Fatalf("got %d observations, want 3 (README.md ignored)", len(obs))
	}
	gotBases := map[string]bool{}
	for _, o := range obs {
		if o.Type != ObservationTypeConfig || o.Source != "recon.MCPConfig" {
			t.Errorf("unexpected observation shape: %+v", o)
		}
		gotBases[filepath.Base(o.Target)] = true
	}
	for _, want := range []string{"config.json", "secrets.env", "UPPER.JSON"} {
		if !gotBases[want] {
			t.Errorf("missing observation for %q; got %v", want, gotBases)
		}
	}
	if gotBases["README.md"] {
		t.Error("README.md should have been ignored")
	}
}

func TestModule_OversizeFileSkipped(t *testing.T) {
	dir := t.TempDir()
	big := make([]byte, maxFileSize+1)
	writeFile(t, dir, "huge.json", string(big))
	writeFile(t, dir, "ok.json", `{"c":3}`)

	m := newModule(t, registry.Config{"path": dir})
	obs, err := m.Recon(context.Background(), nil)
	if err != nil {
		t.Fatalf("Recon() error = %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1 (oversize skipped)", len(obs))
	}
	if filepath.Base(obs[0].Target) != "ok.json" {
		t.Errorf("Target = %q, want ok.json", obs[0].Target)
	}
}

// TestModule_SkipsSymlinks: review finding D — a symlinked config entry inside
// the scanned directory is skipped (a symlink could point outside the tree,
// reading files not under it and bypassing the size cap). Regular files under
// the same directory are still collected.
func TestModule_SkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "real.json", `{"env":{"OK":"value"}}`)

	// A secret-bearing file OUTSIDE the scanned directory.
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte(`{"env":{"GITHUB_TOKEN":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}}`), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	link := filepath.Join(dir, "evil.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	m := newModule(t, registry.Config{"path": dir})
	obs, err := m.Recon(context.Background(), nil)
	if err != nil {
		t.Fatalf("Recon() error = %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1 (symlink skipped)", len(obs))
	}
	if filepath.Base(obs[0].Target) != "real.json" {
		t.Errorf("Target = %q, want real.json (symlink evil.json must not be read)", obs[0].Target)
	}
}

// TestModule_SymlinkedDirRoot: review finding G — when the configured `path` is
// a symlink to a config directory, os.Stat follows it (so it is treated as a
// directory) but WalkDir receives the symlink as its root; the entry-level
// symlink skip would then drop the root and collect zero files (a false clean).
// EvalSymlinks-resolving the root before walking keeps the files collected.
func TestModule_SymlinkedDirRoot(t *testing.T) {
	realDir := t.TempDir()
	writeFile(t, realDir, "config.json", `{"env":{"OK":"value"}}`)
	writeFile(t, realDir, "secrets.env", `API_KEY=abc`)

	link := filepath.Join(t.TempDir(), "cfglink")
	if err := os.Symlink(realDir, link); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	m := newModule(t, registry.Config{"path": link})
	obs, err := m.Recon(context.Background(), nil)
	if err != nil {
		t.Fatalf("Recon() error = %v", err)
	}
	if len(obs) != 2 {
		t.Fatalf("got %d observations, want 2 (files under symlinked dir root)", len(obs))
	}
	gotBases := map[string]bool{}
	for _, o := range obs {
		gotBases[filepath.Base(o.Target)] = true
	}
	for _, want := range []string{"config.json", "secrets.env"} {
		if !gotBases[want] {
			t.Errorf("missing observation for %q; got %v", want, gotBases)
		}
	}
}

// TestModule_SkipsNodeModulesAndHiddenDirs: review finding 5 — the walk must not
// descend into massive/irrelevant subtrees (node_modules, .git, hidden dirs). A
// secret .json inside node_modules is not collected; the top-level config is.
func TestModule_SkipsNodeModulesAndHiddenDirs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.json", `{"env":{"OK":"value"}}`)

	nm := filepath.Join(dir, "node_modules", "pkg")
	if err := os.MkdirAll(nm, 0o750); err != nil {
		t.Fatalf("mkdir node_modules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nm, "secret.json"),
		[]byte(`{"env":{"GITHUB_TOKEN":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}}`), 0o600); err != nil {
		t.Fatalf("write node_modules secret: %v", err)
	}

	hidden := filepath.Join(dir, ".cache")
	if err := os.MkdirAll(hidden, 0o750); err != nil {
		t.Fatalf("mkdir hidden: %v", err)
	}
	if err := os.WriteFile(filepath.Join(hidden, "creds.json"),
		[]byte(`{"env":{"API_KEY":"sk-abcdefghijklmnopqrstuvwxyz0123456789"}}`), 0o600); err != nil {
		t.Fatalf("write hidden secret: %v", err)
	}

	m := newModule(t, registry.Config{"path": dir})
	obs, err := m.Recon(context.Background(), nil)
	if err != nil {
		t.Fatalf("Recon() error = %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1 (node_modules and hidden dirs skipped)", len(obs))
	}
	if filepath.Base(obs[0].Target) != "config.json" {
		t.Errorf("Target = %q, want config.json", obs[0].Target)
	}
}

func TestModule_CancelledContextReturnsErr(t *testing.T) {
	m := newModule(t, registry.Config{"content": `{"env":{"API_KEY":"secret"}}`})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Recon(ctx, nil); err != ctx.Err() {
		t.Errorf("Recon() error = %v, want %v", err, ctx.Err())
	}
}

func TestConfigsFrom_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.json", `{"env":{"TOKEN":"ghp_x"}}`)

	m := newModule(t, registry.Config{"path": dir})
	obs, err := m.Recon(context.Background(), nil)
	if err != nil {
		t.Fatalf("Recon() error = %v", err)
	}
	store := recon.NewStore()
	for _, o := range obs {
		store.Observe(o)
	}
	// An observation of another type must be ignored by ConfigsFrom.
	store.Observe(output.Observation{Type: "some.other.kind", Data: json.RawMessage(`"nope"`)})

	got := ConfigsFrom(store)
	if len(got) != 1 {
		t.Fatalf("ConfigsFrom len = %d, want 1", len(got))
	}
	if filepath.Base(got[0].Source) != "config.json" {
		t.Errorf("Source = %q, want config.json", got[0].Source)
	}
	if got[0].Content != `{"env":{"TOKEN":"ghp_x"}}` {
		t.Errorf("Content = %q, want round-tripped file content", got[0].Content)
	}
}

func TestConfigsFrom_NilStore(t *testing.T) {
	if got := ConfigsFrom(nil); got != nil {
		t.Errorf("ConfigsFrom(nil) = %v, want nil", got)
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}
