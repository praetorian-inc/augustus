package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcpgen "github.com/praetorian-inc/augustus/internal/generators/mcp"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/harnesses"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/recon"
)

var updateSurface = flag.Bool("update", false, "rewrite docs/cli-surface.json from the live registries")

const cliSurfaceSchemaVersion = 1

// cliSurface is the golden snapshot of registered CLI names plus the MCP
// generator's config vocabulary. List() already returns sorted names.
type cliSurface struct {
	SchemaVersion int      `json:"schemaVersion"`
	Generators    []string `json:"generators"`
	Probes        []string `json:"probes"`
	Detectors     []string `json:"detectors"`
	Buffs         []string `json:"buffs"`
	Harnesses     []string `json:"harnesses"`
	Recons        []string `json:"recons"`
	MCP           mcpVocab `json:"mcp"`
}

type mcpVocab struct {
	Generator  string   `json:"generator"`
	Transports []string `json:"transports"`
	Modes      []string `json:"modes"`
	Required   []string `json:"required"`
}

// docTokenRe matches documented family.Name tokens. Only a subset is gated —
// see isGatedDocToken.
var docTokenRe = regexp.MustCompile(`\b((?:mcptool|mcptransport|mcpconfig|mcpprimitive|recon|mcp)\.[A-Za-z0-9_]+)\b`)

func TestCLISurface(t *testing.T) {
	root := repoRoot(t)
	live := snapshotSurface()
	path := filepath.Join(root, "docs", "cli-surface.json")

	if *updateSurface {
		raw, err := marshalSurface(live)
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, raw, 0o644))
		t.Logf("rewrote %s", path)
		return
	}

	raw, err := os.ReadFile(path)
	require.NoErrorf(t, err, "%s is missing; create it with go test ./cmd/augustus -run TestCLISurface -update", path)

	var documented cliSurface
	require.NoError(t, json.Unmarshal(raw, &documented))

	if report := surfaceDrift(live, documented); report != "" {
		require.Fail(t, "CLI surface drift; re-run with -update", report)
	}
}

func TestCLISurfaceDocLint(t *testing.T) {
	root := repoRoot(t)
	registered := registeredNameSet()

	var issues []string
	lint := func(path string) {
		rel, err := filepath.Rel(root, path)
		require.NoError(t, err)
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		for i, line := range strings.Split(string(data), "\n") {
			for _, m := range docTokenRe.FindAllStringSubmatch(line, -1) {
				tok := m[1]
				if !isGatedDocToken(tok) {
					continue
				}
				if _, ok := registered[tok]; ok {
					continue
				}
				issues = append(issues, fmt.Sprintf("%s:%d: %s is not a registered probe, recon module, or generator", rel, i+1, tok))
			}
		}
	}

	readme := filepath.Join(root, "README.md")
	if _, err := os.Stat(readme); err == nil {
		lint(readme)
	}

	docsDir := filepath.Join(root, "docs")
	err := filepath.WalkDir(docsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		lint(path)
		return nil
	})
	require.NoError(t, err)

	if len(issues) > 0 {
		assert.Fail(t, "documentation names unregistered CLI surface tokens", strings.Join(issues, "\n"))
	}
}

func TestCLISurfaceGateDetectsRename(t *testing.T) {
	live := snapshotSurface()
	require.NotEmpty(t, live.Probes, "need at least one registered probe for a rename to be observable")

	documented := slices.Clone(live.Probes)
	mutated := slices.Clone(live.Probes)
	old := mutated[0]
	mutated[0] = old + "Renamed"

	added, removed := setDiff(mutated, documented)
	require.Contains(t, removed, old, "rename must report the old name as removed from live")
	require.Contains(t, added, old+"Renamed", "rename must report the renamed name as added vs documented")
}

func snapshotSurface() cliSurface {
	return cliSurface{
		SchemaVersion: cliSurfaceSchemaVersion,
		Generators:    productionNames(generators.List()),
		Probes:        productionNames(probes.List()),
		Detectors:     productionNames(detectors.List()),
		Buffs:         productionNames(buffs.List()),
		Harnesses:     productionNames(harnesses.List()),
		Recons:        productionNames(recon.List()),
		MCP: mcpVocab{
			Generator:  "mcp.MCP",
			Transports: []string{mcpgen.TransportHTTP, mcpgen.TransportSSE, mcpgen.TransportAuto},
			Modes:      []string{mcpgen.ModeToolCall, mcpgen.ModeListTools},
			Required:   []string{"endpoint"},
		},
	}
}

// productionNames drops test-only registrations (e.g. recon.fakeOK from
// recon_scan_test.go init). Production names are family.ExportedIdent.
func productionNames(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		_, local, ok := strings.Cut(n, ".")
		if !ok || local == "" || local[0] < 'A' || local[0] > 'Z' {
			continue
		}
		out = append(out, n)
	}
	return out
}

func marshalSurface(live cliSurface) ([]byte, error) {
	raw, err := json.MarshalIndent(live, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func surfaceDrift(live, documented cliSurface) string {
	var b strings.Builder
	check := func(family string, liveNames, docNames []string) {
		added, removed := setDiff(liveNames, docNames)
		if len(added) == 0 && len(removed) == 0 {
			return
		}
		fmt.Fprintf(&b, "%s: added %v; removed %v\n", family, added, removed)
	}
	check("generators", live.Generators, documented.Generators)
	check("probes", live.Probes, documented.Probes)
	check("detectors", live.Detectors, documented.Detectors)
	check("buffs", live.Buffs, documented.Buffs)
	check("harnesses", live.Harnesses, documented.Harnesses)
	check("recons", live.Recons, documented.Recons)
	if live.SchemaVersion != documented.SchemaVersion {
		fmt.Fprintf(&b, "schemaVersion: live %d; documented %d\n", live.SchemaVersion, documented.SchemaVersion)
	}
	if live.MCP.Generator != documented.MCP.Generator ||
		!slices.Equal(live.MCP.Transports, documented.MCP.Transports) ||
		!slices.Equal(live.MCP.Modes, documented.MCP.Modes) ||
		!slices.Equal(live.MCP.Required, documented.MCP.Required) {
		fmt.Fprintf(&b, "mcp: live %+v; documented %+v\n", live.MCP, documented.MCP)
	}
	return strings.TrimRight(b.String(), "\n")
}

// setDiff returns names present in live but not documented (added) and names
// present in documented but not live (removed).
func setDiff(live, documented []string) (added, removed []string) {
	docSet := make(map[string]struct{}, len(documented))
	for _, n := range documented {
		docSet[n] = struct{}{}
	}
	liveSet := make(map[string]struct{}, len(live))
	for _, n := range live {
		liveSet[n] = struct{}{}
	}
	for _, n := range live {
		if _, ok := docSet[n]; !ok {
			added = append(added, n)
		}
	}
	for _, n := range documented {
		if _, ok := liveSet[n]; !ok {
			removed = append(removed, n)
		}
	}
	return added, removed
}

func registeredNameSet() map[string]struct{} {
	names := slices.Concat(probes.List(), recon.List(), generators.List())
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		set[n] = struct{}{}
	}
	return set
}

// isGatedDocToken reports whether a regex match looks like a registered CLI
// name. Family prefixes (mcptool./mcptransport./mcpconfig./mcpprimitive./recon.)
// and the exact generator mcp.MCP are gated; other mcp.* tokens (SDK types)
// are not. The local part must be ExportedIdent so filenames (mcpconfig.yaml,
// recon.go) and config keys (recon.settings) are ignored. recon.* package APIs
// (Store, Register, Recon, Run, Registry, ContextAware*) share the prefix but
// are not module IDs — live recon modules are recon.MCP*.
func isGatedDocToken(tok string) bool {
	if tok == "mcp.MCP" {
		return true
	}
	family, name, ok := strings.Cut(tok, ".")
	if !ok || name == "" || name[0] < 'A' || name[0] > 'Z' {
		return false
	}
	switch family {
	case "mcptool", "mcptransport", "mcpconfig", "mcpprimitive":
		return true
	case "recon":
		return strings.HasPrefix(name, "MCP")
	default:
		return false
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			require.FailNow(t, "go.mod not found walking up from working directory")
		}
		dir = parent
	}
}
