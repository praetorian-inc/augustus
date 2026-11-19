package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	litellmgen "github.com/praetorian-inc/augustus/internal/generators/litellm"
	mcpgen "github.com/praetorian-inc/augustus/internal/generators/mcp"
	ollamagen "github.com/praetorian-inc/augustus/internal/generators/ollama"
	openaigen "github.com/praetorian-inc/augustus/internal/generators/openai"
	restgen "github.com/praetorian-inc/augustus/internal/generators/rest"
	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/harnesses"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/recon"
)

var updateSurface = flag.Bool("update", false, "rewrite docs/cli-surface.json from the live registries")

const cliSurfaceSchemaVersion = 1

// cliSurface is the golden snapshot of registered CLI names, the MCP
// generator's config vocabulary, and the config keys each documented
// generator's production parser accepts. List() already returns sorted names.
// Help and error wording is deliberately absent: only key names are pinned.
type cliSurface struct {
	SchemaVersion int      `json:"schemaVersion"`
	Generators    []string `json:"generators"`
	Probes        []string `json:"probes"`
	Detectors     []string `json:"detectors"`
	Buffs         []string `json:"buffs"`
	Harnesses     []string `json:"harnesses"`
	Recons        []string `json:"recons"`
	MCP           mcpVocab `json:"mcp"`
	// GeneratorConfig maps a registered generator name to its parser's keys.
	GeneratorConfig map[string]configKeys `json:"generatorConfig"`
}

type configKeys struct {
	Required []string `json:"required"`
	Optional []string `json:"optional"`
	// Aliases maps a required key to the optional keys accepted in its place.
	Aliases map[string][]string `json:"aliases,omitempty"`
	// EnvFallbacks maps a required key to the environment variable accepted in its place.
	EnvFallbacks map[string]string `json:"envFallbacks,omitempty"`
}

type mcpVocab struct {
	Generator  string   `json:"generator"`
	Transports []string `json:"transports"`
	Modes      []string `json:"modes"`
	Required   []string `json:"required"`
}

// docTokenRe matches documented family.Name tokens. Only a subset is gated —
// see isGatedDocToken.
var docTokenRe = regexp.MustCompile(`\b((?:mcptool|mcptransport|mcpconfig|mcpprimitive|mcpsecrets|recon|mcp)\.[A-Za-z0-9_]+)\b`)

// configParsers lists the generators using-augustus documents, with the
// production parser package (relative to the repo root) and allowlists that
// back each generatorConfig entry. Every non-test file in the package is
// scanned, so a parser helper moved into a new file stays covered; exclude
// names files that parse an out-of-scope generator's config. skipFuncs names
// functions ("Name" or "Recv.Method") whose reads are not the production parse
// path: they are excluded from the equality check but must exist and read only
// allowlisted keys. aliases is nil for a parser with no aliased required key;
// envFallbacks is nil for a parser with no env-satisfiable required key.
var configParsers = []struct {
	names              []string
	dir                string
	exclude            []string
	skipFuncs          []string
	required, optional func() []string
	aliases            func() map[string][]string
	envFallbacks       func() map[string]string
}{
	{[]string{"litellm.LiteLLM"}, "internal/generators/litellm", nil, nil, litellmgen.RequiredKeys, litellmgen.OptionalKeys, litellmgen.KeyAliases, nil},
	{[]string{"mcp.MCP"}, "internal/generators/mcp", nil, nil, mcpgen.RequiredKeys, mcpgen.OptionalKeys, mcpgen.KeyAliases, nil},
	{[]string{"ollama.Ollama", "ollama.OllamaChat"}, "internal/generators/ollama", nil, nil, ollamagen.RequiredKeys, ollamagen.OptionalKeys, nil, nil},
	// openai.OpenAIReasoning (reasoning*.go) has its own parser and is not documented by using-augustus (out of scope for ENG-8420).
	{[]string{"openai.OpenAI"}, "internal/generators/openai", []string{"reasoning.go", "reasoning_config.go"}, nil, openaigen.RequiredKeys, openaigen.OptionalKeys, nil, openaigen.KeyEnvFallbacks},
	// ConfigFromMap has no production caller; NewRest is the parser, so its
	// overlapping reads must not mask a key NewRest stops reading.
	{[]string{"rest.Rest"}, "internal/generators/rest", nil, []string{"ConfigFromMap"}, restgen.RequiredKeys, restgen.OptionalKeys, restgen.KeyAliases, nil},
}

func TestCLISurface(t *testing.T) {
	root := repoRoot(t)
	requireAllowlistsMatchParsers(t, root)
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

// requireAllowlistsMatchParsers fails when a parser reads a key its allowlist
// omits (or lists a key it never reads) outside its skipFuncs, when a skipped
// function is absent or reads a non-allowlisted key, or when a key is both required and
// optional, when an alias maps a non-required key or names a key outside
// the optional list, or when an env fallback maps a non-required key, so the snapshot cannot be rewritten from a stale allowlist.
func requireAllowlistsMatchParsers(t *testing.T, root string) {
	t.Helper()
	for _, p := range configParsers {
		files, err := testutil.PackageSources(filepath.Join(root, p.dir), p.exclude...)
		require.NoError(t, err)
		byFunc, err := testutil.ConfigKeysReadByFunc(files...)
		require.NoError(t, err)
		required, optional := p.required(), p.optional()
		allowed := slices.Concat(required, optional)
		read := map[string]struct{}{}
		for fn, keys := range byFunc {
			if slices.Contains(p.skipFuncs, fn) {
				continue
			}
			for _, k := range keys {
				read[k] = struct{}{}
			}
		}
		require.ElementsMatchf(t, allowed, slices.Collect(maps.Keys(read)),
			"%v: RequiredKeys()+OptionalKeys() must equal the keys %s reads outside %v", p.names, p.dir, p.skipFuncs)
		for _, fn := range p.skipFuncs {
			keys, ok := byFunc[fn]
			require.Truef(t, ok, "%v: skipped function %s reads no config key in %s (stale skipFuncs entry)", p.names, fn, p.dir)
			require.Subsetf(t, allowed, keys, "%v: skipped function %s in %s reads a key outside RequiredKeys()+OptionalKeys()", p.names, fn, p.dir)
		}
		for _, k := range required {
			require.NotContainsf(t, optional, k, "%v: key %q is both required and optional", p.names, k)
		}
		aliases := sortedAliases(p.aliases)
		for _, k := range slices.Sorted(maps.Keys(aliases)) {
			require.Containsf(t, required, k, "%v: aliased key %q is not required", p.names, k)
			for _, a := range aliases[k] {
				require.Containsf(t, optional, a, "%v: alias %q of %q is not optional", p.names, a, k)
			}
		}
		fallbacks := cloneEnvFallbacks(p.envFallbacks)
		for _, k := range slices.Sorted(maps.Keys(fallbacks)) {
			require.Containsf(t, required, k, "%v: env-satisfiable key %q is not required", p.names, k)
		}
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
				issues = append(issues, fmt.Sprintf("%s:%d: %s is not a registered probe, recon module, generator, or detector", rel, i+1, tok))
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
	t.Run("probe name", func(t *testing.T) {
		live := snapshotSurface()
		require.NotEmpty(t, live.Probes, "need at least one registered probe for a rename to be observable")

		documented := slices.Clone(live.Probes)
		mutated := slices.Clone(live.Probes)
		old := mutated[0]
		mutated[0] = old + "Renamed"

		added, removed := setDiff(mutated, documented)
		require.Contains(t, removed, old, "rename must report the old name as removed from live")
		require.Contains(t, added, old+"Renamed", "rename must report the renamed name as added vs documented")
	})

	t.Run("generator config key", func(t *testing.T) {
		documented := snapshotSurface()
		live := snapshotSurface()
		keys := live.GeneratorConfig["mcp.MCP"]
		require.NotEmpty(t, keys.Optional, "need at least one optional mcp.MCP key for a rename to be observable")
		old := keys.Optional[0]
		keys.Optional = slices.Clone(keys.Optional)
		keys.Optional[0] = old + "_renamed"
		live.GeneratorConfig["mcp.MCP"] = keys

		report := surfaceDrift(live, documented)
		require.Contains(t, report, "generatorConfig mcp.MCP optional: added ["+old+"_renamed]; removed ["+old+"]")
	})

	t.Run("generator config alias", func(t *testing.T) {
		documented := snapshotSurface()
		live := snapshotSurface()
		keys := live.GeneratorConfig["mcp.MCP"]
		require.NotEmpty(t, keys.Aliases["endpoint"], "need an mcp.MCP endpoint alias for a rename to be observable")
		old := keys.Aliases["endpoint"][0]
		renamed := slices.Clone(keys.Aliases["endpoint"])
		renamed[0] = old + "_renamed"
		keys.Aliases = map[string][]string{"endpoint": renamed}
		live.GeneratorConfig["mcp.MCP"] = keys

		report := surfaceDrift(live, documented)
		require.Contains(t, report, "generatorConfig mcp.MCP aliases: added [endpoint="+old+"_renamed]; removed [endpoint="+old+"]")
	})

	t.Run("generator config env fallback", func(t *testing.T) {
		documented := snapshotSurface()
		require.Equal(t, "OPENAI_API_KEY", documented.GeneratorConfig["openai.OpenAI"].EnvFallbacks["api_key"],
			"need an openai.OpenAI api_key env fallback for a rename to be observable")

		renamed := snapshotSurface()
		keys := renamed.GeneratorConfig["openai.OpenAI"]
		keys.EnvFallbacks = map[string]string{"api_key": "OPENAI_API_KEY_RENAMED"}
		renamed.GeneratorConfig["openai.OpenAI"] = keys
		require.Contains(t, surfaceDrift(renamed, documented),
			"generatorConfig openai.OpenAI envFallbacks: added [api_key=OPENAI_API_KEY_RENAMED]; removed [api_key=OPENAI_API_KEY]")

		dropped := snapshotSurface()
		keys = dropped.GeneratorConfig["openai.OpenAI"]
		keys.EnvFallbacks = nil
		dropped.GeneratorConfig["openai.OpenAI"] = keys
		require.Contains(t, surfaceDrift(dropped, documented),
			"generatorConfig openai.OpenAI envFallbacks: added []; removed [api_key=OPENAI_API_KEY]")
	})

	// The per-entry key diff iterates live names only, so a generator dropped
	// from configParsers must still surface through the entry-name diff.
	t.Run("generator config entry dropped", func(t *testing.T) {
		documented := snapshotSurface()
		live := snapshotSurface()
		require.Contains(t, live.GeneratorConfig, "rest.Rest")
		delete(live.GeneratorConfig, "rest.Rest")

		report := surfaceDrift(live, documented)
		require.Contains(t, report, "generatorConfig: added []; removed [rest.Rest]")
	})
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
			Transports: mcpgen.Transports(),
			Modes:      mcpgen.Modes(),
			Required:   mcpgen.RequiredKeys(),
		},
		GeneratorConfig: generatorConfig(),
	}
}

func generatorConfig() map[string]configKeys {
	out := make(map[string]configKeys)
	for _, p := range configParsers {
		keys := configKeys{
			Required:     slices.Sorted(slices.Values(p.required())),
			Optional:     slices.Sorted(slices.Values(p.optional())),
			Aliases:      sortedAliases(p.aliases),
			EnvFallbacks: cloneEnvFallbacks(p.envFallbacks),
		}
		for _, name := range p.names {
			out[name] = keys
		}
	}
	return out
}

// sortedAliases copies a parser's alias map with each alias list sorted, or
// returns nil when the parser declares no aliases.
func sortedAliases(aliases func() map[string][]string) map[string][]string {
	if aliases == nil {
		return nil
	}
	out := make(map[string][]string)
	for k, v := range aliases() {
		out[k] = slices.Sorted(slices.Values(v))
	}
	return out
}

// aliasPairs flattens an alias map to sorted "key=alias" strings for setDiff.
func aliasPairs(aliases map[string][]string) []string {
	var out []string
	for k, v := range aliases {
		for _, a := range v {
			out = append(out, k+"="+a)
		}
	}
	slices.Sort(out)
	return out
}

// cloneEnvFallbacks copies a parser's env fallback map, or returns nil when
// the parser declares no env fallbacks.
func cloneEnvFallbacks(fallbacks func() map[string]string) map[string]string {
	if fallbacks == nil {
		return nil
	}
	return maps.Clone(fallbacks())
}

// envFallbackPairs flattens an env fallback map to sorted "key=VAR" strings
// for setDiff.
func envFallbackPairs(fallbacks map[string]string) []string {
	var out []string
	for k, v := range fallbacks {
		out = append(out, k+"="+v)
	}
	slices.Sort(out)
	return out
}

// productionNames drops test-only registrations (e.g. recon.fakeOK from
// recon_scan_test.go init, or test.ProbeCfgLeakSentinel whose local part is
// exported). Production names are family.ExportedIdent; family "test" names
// are kept unless the local part contains "Sentinel" (test-file sentinels
// that pollute List() under -shuffle). Public CLI names such as test.Blank
// and test.Repeat stay in the snapshot.
func productionNames(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		family, local, ok := strings.Cut(n, ".")
		if !ok || local == "" || local[0] < 'A' || local[0] > 'Z' {
			continue
		}
		if family == "test" && strings.Contains(local, "Sentinel") {
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
	check("generatorConfig", slices.Sorted(maps.Keys(live.GeneratorConfig)), slices.Sorted(maps.Keys(documented.GeneratorConfig)))
	for _, name := range slices.Sorted(maps.Keys(live.GeneratorConfig)) {
		doc, ok := documented.GeneratorConfig[name]
		if !ok {
			continue
		}
		check("generatorConfig "+name+" required", live.GeneratorConfig[name].Required, doc.Required)
		check("generatorConfig "+name+" optional", live.GeneratorConfig[name].Optional, doc.Optional)
		check("generatorConfig "+name+" aliases", aliasPairs(live.GeneratorConfig[name].Aliases), aliasPairs(doc.Aliases))
		check("generatorConfig "+name+" envFallbacks", envFallbackPairs(live.GeneratorConfig[name].EnvFallbacks), envFallbackPairs(doc.EnvFallbacks))
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
	names := slices.Concat(probes.List(), recon.List(), generators.List(), detectors.List())
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		set[n] = struct{}{}
	}
	return set
}

// isGatedDocToken reports whether a regex match looks like a registered CLI
// name. Family prefixes (mcptool./mcptransport./mcpconfig./mcpprimitive./mcpsecrets./recon.)
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
	case "mcptool", "mcptransport", "mcpconfig", "mcpprimitive", "mcpsecrets":
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
