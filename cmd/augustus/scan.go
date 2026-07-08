package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/praetorian-inc/augustus/pkg/cli"
	"github.com/praetorian-inc/augustus/pkg/config"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/harnesses"
	"github.com/praetorian-inc/augustus/pkg/hooks"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/results"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// scanConfig holds the configuration for a scan command.
type scanConfig struct {
	generatorName   string
	probeNames      []string
	detectorNames   []string
	buffNames       []string
	harnessName     string
	configFile      string // YAML config file path
	configJSON      string
	outputFormat    string
	outputFile      string // JSONL output file path
	htmlFile        string // HTML report file path
	verbose         bool
	allProbes       bool          // Run all registered probes
	timeout         time.Duration // Overall scan timeout
	concurrency     int           // Max concurrent probes
	probeTimeout    time.Duration // Per-probe timeout
	setup           string        // Shell command: once before all probes
	prepare         string        // Shell command: before each probe
	cleanup         string        // Shell command: after all probes
	refusalPatterns []string      // Target refusal/guardrail phrases for mitigation.* detectors
}

// Kong helper methods

func (s *ScanCmd) execute() error {
	cfg := s.loadScanConfig()

	if err := s.expandGlobPatterns(cfg); err != nil {
		return err
	}

	// Load YAML config if provided
	var yamlCfg *config.Config
	if cfg.configFile != "" {
		var err error
		yamlCfg, err = config.LoadConfig(cfg.configFile)
		if err != nil {
			return fmt.Errorf("failed to load config file: %w", err)
		}
	}

	// Resolve all configuration via unified precedence
	cli := s.buildCLIOverrides()
	resolved, err := config.Resolve(yamlCfg, cli)
	if err != nil {
		return fmt.Errorf("failed to resolve configuration: %w", err)
	}

	// Create streaming JSONL writer if output path specified.
	// When streaming is active, JSONL is written incrementally per-attempt,
	// so the collectingEvaluator only handles HTML output.
	var streamWriter *results.StreamWriter
	var onAttemptProcessed func(*attempt.Attempt)
	collectJSONLPath := resolved.OutputFile
	if resolved.OutputFile != "" {
		streamWriter, err = results.NewStreamWriter(resolved.OutputFile)
		if err != nil {
			return fmt.Errorf("failed to create stream writer: %w", err)
		}
		defer func() { _ = streamWriter.Close() }()
		onAttemptProcessed = streamWriter.Append
		collectJSONLPath = "" // Streaming handles JSONL; don't double-write
	}

	eval := s.createEvaluator(&scanConfig{
		outputFormat: resolved.OutputFormat,
		outputFile:   collectJSONLPath,
		htmlFile:     resolved.HTMLFile,
		verbose:      s.Verbose,
	})
	ctx, cancel := s.setupContext()
	defer cancel()

	return runScanResolved(ctx, cfg, yamlCfg, resolved, eval, onAttemptProcessed)
}

// loadScanConfig converts Kong struct to legacy scanConfig
func (s *ScanCmd) loadScanConfig() *scanConfig {
	return &scanConfig{
		generatorName:   s.Generator,
		probeNames:      s.Probe,
		detectorNames:   s.Detectors,
		buffNames:       s.Buff,
		harnessName:     s.Harness,
		configFile:      s.ConfigFile,
		configJSON:      s.Config,
		outputFormat:    s.Format,
		outputFile:      s.Output,
		htmlFile:        s.HTML,
		verbose:         s.Verbose,
		allProbes:       s.All,
		timeout:         s.Timeout,
		concurrency:     s.Concurrency,
		probeTimeout:    s.ProbeTimeout,
		setup:           s.Setup,
		prepare:         s.Prepare,
		cleanup:         s.Cleanup,
		refusalPatterns: s.RefusalPattern,
	}
}

// buildCLIOverrides creates CLIOverrides from ScanCmd fields.
// Zero-value fields mean "not set" (since Kong defaults were removed in Task 10).
func (s *ScanCmd) buildCLIOverrides() config.CLIOverrides {
	cli := config.CLIOverrides{
		GeneratorName: s.Generator,
		ConfigJSON:    s.Config,
		HTMLFile:      s.HTML,
		ProfileName:   s.Profile,
	}

	// Merge --model into ConfigJSON (takes precedence over --config model key)
	if s.Model != "" {
		if cli.ConfigJSON == "" {
			cli.ConfigJSON = `{"model":"` + s.Model + `"}`
		} else {
			var cfgMap map[string]any
			if err := json.Unmarshal([]byte(cli.ConfigJSON), &cfgMap); err == nil {
				cfgMap["model"] = s.Model
				if b, err := json.Marshal(cfgMap); err == nil {
					cli.ConfigJSON = string(b)
				}
			}
		}
	}

	if s.Concurrency > 0 {
		cli.Concurrency = &s.Concurrency
	}
	if s.Timeout > 0 {
		cli.Timeout = &s.Timeout
	}
	if s.ProbeTimeout > 0 {
		cli.ProbeTimeout = &s.ProbeTimeout
	}
	if s.Format != "" {
		cli.OutputFormat = s.Format
	}
	if s.Output != "" {
		cli.OutputFile = s.Output
	}

	return cli
}

// expandGlobPatterns handles glob pattern expansion for probes and detectors
func (s *ScanCmd) expandGlobPatterns(cfg *scanConfig) error {
	// Handle glob patterns for probes
	if s.ProbesGlob != "" {
		matches, err := cli.ParseCommaSeparatedGlobs(s.ProbesGlob, probes.List())
		if err != nil {
			return fmt.Errorf("invalid --probes-glob: %w", err)
		}
		if len(matches) == 0 {
			return fmt.Errorf("no probes match pattern: %s", s.ProbesGlob)
		}
		cfg.probeNames = matches
	}

	// Handle glob patterns for detectors
	if s.DetectorsGlob != "" {
		matches, err := cli.ParseCommaSeparatedGlobs(s.DetectorsGlob, detectors.List())
		if err != nil {
			return fmt.Errorf("invalid --detectors-glob: %w", err)
		}
		if len(matches) == 0 {
			return fmt.Errorf("no detectors match pattern: %s", s.DetectorsGlob)
		}
		cfg.detectorNames = matches
	}

	// Handle glob patterns for buffs
	if s.BuffsGlob != "" {
		matches, err := cli.ParseCommaSeparatedGlobs(s.BuffsGlob, buffs.List())
		if err != nil {
			return fmt.Errorf("invalid --buffs-glob: %w", err)
		}
		if len(matches) == 0 {
			return fmt.Errorf("no buffs match pattern: %s", s.BuffsGlob)
		}
		cfg.buffNames = matches
	}

	return nil
}

// createEvaluator creates evaluator based on output format
func (s *ScanCmd) createEvaluator(cfg *scanConfig) harnesses.Evaluator {
	var eval harnesses.Evaluator
	switch cfg.outputFormat {
	case "json":
		eval = &jsonEvaluator{}
	case "jsonl":
		eval = &jsonlEvaluator{}
	default:
		eval = &tableEvaluator{verbose: cfg.verbose}
	}

	// Wrap evaluator with file output if needed
	if cfg.outputFile != "" || cfg.htmlFile != "" {
		eval = &collectingEvaluator{
			inner:     eval,
			jsonlPath: cfg.outputFile,
			htmlPath:  cfg.htmlFile,
		}
	}

	return eval
}

// setupContext creates a context with signal handling for graceful shutdown.
// Scan timeout is handled by the scanner package, not the context, so that
// partial results can still be processed after the scanning phase completes.
func (s *ScanCmd) setupContext() (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	return ctx, stop
}

// runScan is a test helper that wraps runScanResolved with config resolution.
// This maintains backward compatibility for existing tests.
func runScan(ctx context.Context, cfg *scanConfig, eval harnesses.Evaluator) error {
	// Load YAML config if provided
	var yamlCfg *config.Config
	if cfg.configFile != "" {
		var err error
		yamlCfg, err = config.LoadConfig(cfg.configFile)
		if err != nil {
			return fmt.Errorf("failed to load config file: %w", err)
		}
	}

	// Build CLI overrides from scanConfig
	cli := config.CLIOverrides{
		GeneratorName: cfg.generatorName,
		ConfigJSON:    cfg.configJSON,
		OutputFormat:  cfg.outputFormat,
		OutputFile:    cfg.outputFile,
		HTMLFile:      cfg.htmlFile,
	}
	if cfg.concurrency > 0 {
		cli.Concurrency = &cfg.concurrency
	}
	if cfg.timeout > 0 {
		cli.Timeout = &cfg.timeout
	}
	if cfg.probeTimeout > 0 {
		cli.ProbeTimeout = &cfg.probeTimeout
	}

	// Resolve configuration
	resolved, err := config.Resolve(yamlCfg, cli)
	if err != nil {
		return fmt.Errorf("failed to resolve configuration: %w", err)
	}

	return runScanResolved(ctx, cfg, yamlCfg, resolved, eval, nil)
}

// createProbes creates probe instances from probe names.
// Injects target generator type and config into probe config so PAIR/TAP can inherit them.
func createProbes(probeNames []string, yamlCfg *config.Config, targetGeneratorName string, targetGeneratorConfig registry.Config) ([]probes.Prober, error) {
	probeList := make([]probes.Prober, 0, len(probeNames))
	for _, probeName := range probeNames {
		var probeCfg registry.Config
		if yamlCfg != nil {
			probeCfg = yamlCfg.ResolveProbeConfig(probeName)
		} else {
			probeCfg = make(registry.Config)
		}

		// Inject target generator type and model config for PAIR/TAP inheritance
		// Only inject if not already explicitly configured in YAML
		if _, hasTargetType := probeCfg["target_generator_type"]; !hasTargetType {
			slog.Debug("probe inheriting target generator type", "probe", probeName, "type", targetGeneratorName)
			probeCfg["target_generator_type"] = targetGeneratorName
		}
		// Inject base model config if not already present
		if _, hasModel := probeCfg["model"]; !hasModel {
			if model, ok := targetGeneratorConfig["model"]; ok {
				probeCfg["model"] = model
			}
		}

		probe, err := probes.Create(probeName, probeCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create probe %s: %w", probeName, err)
		}
		probeList = append(probeList, probe)
	}
	return probeList, nil
}

// refusalPatternDetectors is the set of detectors whose recognized
// refusal/guardrail phrase list is augmented by --refusal-pattern. Every entry
// resolves its phrases through base.ResolveMitigationPhrases (via extra_substrings),
// so a target's custom guardrail phrasing is recognized consistently and a
// non-generic deflection is not mis-scored (LAB-4664). Keep this list in sync
// with the detectors that embed base.MitigationStrings.
var refusalPatternDetectors = []string{
	"mitigation.MitigationBypass",
	"mitigation.Prefixes",
	"multiagent.OrchestratorDetector",
	"multiagent.Detector",
	"latentinjection.Detector",
	"pair.PAIR",
	"divergence.RepeatDiverges",
}

// applyRefusalPatterns merges operator-supplied refusal phrases (from
// --refusal-pattern) into the extra_substrings config of every
// mitigation/refusal-based detector (refusalPatternDetectors) so they recognize
// a target's custom guardrail phrasing and do not mis-score a non-generic
// deflection as a bypass (LAB-4664). The patterns augment (never replace) any
// extra_substrings already present in YAML.
//
// Returns the config to thread through the rest of the scan; when patterns is
// empty the input is returned unchanged. A nil yamlCfg is materialized into a
// fresh Config only when there are patterns to inject.
func applyRefusalPatterns(yamlCfg *config.Config, patterns []string) *config.Config {
	if len(patterns) == 0 {
		return yamlCfg
	}
	if yamlCfg == nil {
		yamlCfg = &config.Config{}
	}
	if yamlCfg.Detectors.Settings == nil {
		yamlCfg.Detectors.Settings = make(map[string]map[string]any)
	}
	for _, name := range refusalPatternDetectors {
		settings := yamlCfg.Detectors.Settings[name]
		if settings == nil {
			settings = make(map[string]any)
		}
		settings["extra_substrings"] = mergeExtraSubstrings(settings["extra_substrings"], patterns)
		yamlCfg.Detectors.Settings[name] = settings
	}
	return yamlCfg
}

// mergeExtraSubstrings appends patterns to an existing extra_substrings config
// value (which may be nil, []string, or []any parsed from YAML) and returns the
// combined []string.
func mergeExtraSubstrings(existing any, patterns []string) []string {
	var out []string
	switch v := existing.(type) {
	case []string:
		out = append(out, v...)
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
	}
	out = append(out, patterns...)
	return out
}

// createDetectors creates detector instances from explicit names or auto-discovers from probes.
func createDetectors(detectorNames []string, probeList []probes.Prober, yamlCfg *config.Config) ([]detectors.Detector, error) {
	var detectorList []detectors.Detector

	if len(detectorNames) > 0 {
		// Explicit detector names provided
		detectorList = make([]detectors.Detector, 0, len(detectorNames))
		for _, detectorName := range detectorNames {
			var detCfg registry.Config
			if yamlCfg != nil {
				detCfg = yamlCfg.ResolveDetectorConfig(detectorName)
			} else {
				detCfg = make(registry.Config)
			}

			detector, err := detectors.Create(detectorName, detCfg)
			if err != nil {
				return nil, fmt.Errorf("failed to create detector %s: %w", detectorName, err)
			}
			detectorList = append(detectorList, detector)
		}
	} else {
		// Auto-discover detectors from probe metadata
		uniqueDetectors := make(map[string]struct{})
		for _, probe := range probeList {
			if pm, ok := probe.(types.ProbeMetadata); ok {
				uniqueDetectors[pm.GetPrimaryDetector()] = struct{}{}
			}
		}
		for detectorName := range uniqueDetectors {
			var detCfg registry.Config
			if yamlCfg != nil {
				detCfg = yamlCfg.ResolveDetectorConfig(detectorName)
			} else {
				detCfg = make(registry.Config)
			}

			detector, err := detectors.Create(detectorName, detCfg)
			if err != nil {
				return nil, fmt.Errorf("failed to create detector %s: %w", detectorName, err)
			}

			// Validate ToolManipulation has required config when auto-discovered from probes.
			// Without expected_tools or forbidden_tools the detector always scores 0.0.
			if detectorName == "agent.ToolManipulation" {
				if !hasConfigList(detCfg, "expected_tools") && !hasConfigList(detCfg, "forbidden_tools") {
					return nil, fmt.Errorf(
						"detector agent.ToolManipulation requires expected_tools or forbidden_tools in config — " +
							"probes using this detector will always score 0.0 without configuration. " +
							"Set via --config-file YAML or --detector-config flag",
					)
				}
			}

			detectorList = append(detectorList, detector)
		}
		if len(detectorList) == 0 {
			return nil, errors.New("no detectors available")
		}
	}

	return detectorList, nil
}

// buildProbeDetectorMap builds a map of probe name → per-probe detector list
// for probes that implement ProbeDetectorConfig (non-empty detector_config) or
// ProbeSecondaryDetectors (non-empty secondary_detectors list), or both.
//
// Primary detector logic (ProbeDetectorConfig): the probe's detector_config is
// merged on top of the global YAML config for the primary detector, and the
// resulting instance is placed first in the slice.
//
// Secondary detector logic (ProbeSecondaryDetectors): for each secondary entry,
// a fresh detector instance is created by merging the secondary's Config on top
// of the global YAML config for that detector name, and appended to the slice.
//
// Probes with neither interface (or with empty configs and no secondaries) are
// absent from the returned map; their callers fall back to the shared detectorList.
func buildProbeDetectorMap(probeList []probes.Prober, detectorList []detectors.Detector, yamlCfg *config.Config) (map[string][]detectors.Detector, error) {
	overrides := make(map[string][]detectors.Detector)

	for _, probe := range probeList {
		pdc, hasPrimary := probe.(types.ProbeDetectorConfig)
		psd, hasSecondary := probe.(types.ProbeSecondaryDetectors)

		// Neither interface implemented → no override needed.
		if !hasPrimary && !hasSecondary {
			continue
		}

		// ProbeDetectorConfig present but empty config AND no secondaries → skip
		// (same early-exit as before, but now gated on both being absent/empty).
		var probeCfg map[string]any
		if hasPrimary {
			probeCfg = pdc.GetDetectorConfig()
		}
		var secondaries []types.SecondaryDetector
		if hasSecondary {
			secondaries = psd.GetSecondaryDetectors()
		}
		if len(probeCfg) == 0 && len(secondaries) == 0 {
			continue
		}

		probeDetectors := make([]detectors.Detector, 0, len(detectorList)+len(secondaries))

		// --- Primary detectors ---
		// Build primary list unconditionally: probe's declared primary first (hoisted),
		// then any user-selected detectors deduped. Always run primaries — even when
		// probeCfg is empty, the secondary must NOT replace the primary detector list.
		// When probeCfg is empty, mergeCfgs(baseCfg, probeCfg) returns baseCfg unchanged,
		// so the primary gets the global YAML config as if it were not in the override map.
		{
			seen := make(map[string]bool, len(detectorList))
			var primaryName string
			var primaryNames []string
			if pm, ok := probe.(types.ProbeMetadata); ok {
				if primary := pm.GetPrimaryDetector(); primary != "" {
					primaryName = primary
					primaryNames = append(primaryNames, primary)
					seen[primary] = true
				}
			}
			for _, d := range detectorList {
				if !seen[d.Name()] {
					primaryNames = append(primaryNames, d.Name())
					seen[d.Name()] = true
				}
			}

			for _, detectorName := range primaryNames {
				baseCfg := resolveDetectorBaseCfg(yamlCfg, detectorName)
				mergedCfg := baseCfg
				if detectorName == primaryName {
					mergedCfg = mergeCfgs(baseCfg, probeCfg)
				}

				d, err := detectors.Create(detectorName, mergedCfg)
				if err != nil {
					return nil, fmt.Errorf("failed to create per-probe detector %s for probe %s: %w", detectorName, probe.Name(), err)
				}
				probeDetectors = append(probeDetectors, d)
			}
		}

		// --- Secondary detectors ---
		for _, sec := range secondaries {
			baseCfg := resolveDetectorBaseCfg(yamlCfg, sec.Name)
			mergedCfg := mergeCfgs(baseCfg, sec.Config)

			d, err := detectors.Create(sec.Name, mergedCfg)
			if err != nil {
				return nil, fmt.Errorf("failed to create secondary detector %s for probe %s: %w", sec.Name, probe.Name(), err)
			}
			probeDetectors = append(probeDetectors, d)
		}

		if len(probeDetectors) > 0 {
			overrides[probe.Name()] = probeDetectors
		}
	}

	return overrides, nil
}

// resolveDetectorBaseCfg returns the global YAML config for a detector, or an
// empty Config when yamlCfg is nil.
func resolveDetectorBaseCfg(yamlCfg *config.Config, detectorName string) registry.Config {
	if yamlCfg != nil {
		return yamlCfg.ResolveDetectorConfig(detectorName)
	}
	return make(registry.Config)
}

// mergeCfgs returns a new Config that is the union of base and override, with
// override winning on key conflicts. Either argument may be nil.
func mergeCfgs(base, override map[string]any) registry.Config {
	merged := make(registry.Config, len(base)+len(override))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range override {
		merged[k] = v
	}
	return merged
}

// hasConfigList returns true when cfg[key] contains at least one usable string
// value. Used for load-time validation of detectors that require at least one
// list-valued config key (e.g. expected_tools/forbidden_tools).
//
// Fix 4 — []any element-type validation: a []any slice whose elements are all
// non-strings (e.g. []any{123}) previously passed this guard because the check
// was len(list) > 0. However, parseStringList (the function that the detector
// actually uses to parse the same config) silently drops non-string items,
// leaving the detector with an empty slice that scores 0.0 — re-opening the
// fail-open the guard exists to prevent. The fix counts only string-typed
// elements, matching the actual parsing behavior.
func hasConfigList(cfg registry.Config, key string) bool {
	v, ok := cfg[key]
	if !ok {
		return false
	}
	switch list := v.(type) {
	case []string:
		return len(list) > 0
	case []any:
		// Mirror parseStringList: only string elements are usable.
		for _, item := range list {
			if _, ok := item.(string); ok {
				return true
			}
		}
		return false
	case string:
		return list != ""
	default:
		return false
	}
}

// createAndApplyBuffs creates buff instances and applies them to probes.
func createAndApplyBuffs(probeList []probes.Prober, buffNames []string, yamlCfg *config.Config) ([]probes.Prober, error) {
	if len(buffNames) == 0 {
		return probeList, nil
	}

	buffList := make([]buffs.Buff, 0, len(buffNames))
	for _, buffName := range buffNames {
		buffCfg := registry.Config{}
		if yamlCfg != nil {
			buffCfg = yamlCfg.ResolveBuffConfig(buffName)
		}
		buff, err := buffs.Create(buffName, buffCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create buff %s: %w", buffName, err)
		}
		buffList = append(buffList, buff)
	}

	buffChain := buffs.NewBuffChain(buffList...)
	if buffChain.IsEmpty() {
		return probeList, nil
	}

	wrappedProbes := make([]probes.Prober, len(probeList))
	for i, probe := range probeList {
		wrappedProbes[i] = buffs.NewBuffedProber(probe, buffChain)
	}

	return wrappedProbes, nil
}

// runScanResolved executes the scan with resolved configuration.
func runScanResolved(ctx context.Context, cfg *scanConfig, yamlCfg *config.Config, resolved *config.ResolvedConfig, eval harnesses.Evaluator, onAttemptProcessed func(*attempt.Attempt)) error {
	// Resolve runtime hooks: YAML config provides defaults, CLI flags override.
	if yamlCfg != nil {
		if cfg.setup == "" && yamlCfg.Hooks.Setup != "" {
			cfg.setup = yamlCfg.Hooks.Setup
		}
		if cfg.prepare == "" && yamlCfg.Hooks.Prepare != "" {
			cfg.prepare = yamlCfg.Hooks.Prepare
		}
		if cfg.cleanup == "" && yamlCfg.Hooks.Cleanup != "" {
			cfg.cleanup = yamlCfg.Hooks.Cleanup
		}
	}

	// Runtime hooks: run setup hook before scan
	var setupVars map[string]string
	if cfg.setup != "" || cfg.prepare != "" || cfg.cleanup != "" {
		// Force sequential execution when hooks are used (stateful scanning)
		if resolved.ScannerOpts.Concurrency > 1 {
			slog.Warn("forcing concurrency=1 because runtime hooks require sequential execution")
			resolved.ScannerOpts.Concurrency = 1
		}
	}
	if cfg.setup != "" {
		slog.Info("running setup hook")
		setupHook := &hooks.Hook{Command: cfg.setup}
		result, err := setupHook.Run(ctx, map[string]string{
			"AUGUSTUS_GENERATOR": cfg.generatorName,
		})
		if err != nil {
			return fmt.Errorf("setup hook failed: %w", err)
		}
		setupVars = result.Variables
		// Merge setup variables into generator config with HOOK_ prefix
		// to prevent overriding reserved keys like uri, method, proxy
		for k, v := range setupVars {
			prefixedKey := "HOOK_" + k
			if _, exists := resolved.GeneratorConfig[k]; exists {
				slog.Warn("setup hook variable collides with config key, using prefixed key", "key", k, "prefixed", prefixedKey)
			}
			resolved.GeneratorConfig[prefixedKey] = v
		}
		if len(setupVars) > 0 {
			slog.Info("setup hook injected variables", "count", len(setupVars))
		}
	}

	// Create generator
	gen, err := generators.Create(cfg.generatorName, resolved.GeneratorConfig)
	if err != nil {
		return fmt.Errorf("failed to create generator %s: %w", cfg.generatorName, err)
	}

	// Wrap generator with runtime hooks if prepare is configured
	if cfg.prepare != "" || len(setupVars) > 0 {
		var prepareHook *hooks.Hook
		if cfg.prepare != "" {
			prepareHook = &hooks.Hook{Command: cfg.prepare}
		}
		gen = hooks.NewHookedGenerator(gen, prepareHook, setupVars)
	}

	// Get probe names
	probeNames := cfg.probeNames
	if cfg.allProbes {
		probeNames = probes.List()
		fmt.Printf("Running all %d registered probes\n", len(probeNames))

		// Warn about multi-turn probes that need explicit configuration
		multiTurnProbes := []string{
			"crescendo.Crescendo",
			"goat.Goat",
			"hydra.Hydra",
			"mischievous.MischievousUser",
		}
		var unconfigured []string
		for _, mt := range multiTurnProbes {
			if yamlCfg == nil || !yamlCfg.HasProbeConfig(mt) {
				unconfigured = append(unconfigured, mt)
			}
		}
		if len(unconfigured) > 0 {
			fmt.Fprintf(os.Stderr, "WARNING: Multi-turn probes require explicit configuration (goal, attacker/judge models).\n")
			fmt.Fprintf(os.Stderr, "  Unconfigured: %s\n", strings.Join(unconfigured, ", "))
			fmt.Fprintf(os.Stderr, "  These probes will be skipped. Use --config-file to provide settings.\n")
			// Filter out unconfigured multi-turn probes
			skip := make(map[string]bool, len(unconfigured))
			for _, name := range unconfigured {
				skip[name] = true
			}
			filtered := probeNames[:0]
			for _, name := range probeNames {
				if !skip[name] {
					filtered = append(filtered, name)
				}
			}
			probeNames = filtered
		}
	}

	// Create probes
	probeList, err := createProbes(probeNames, yamlCfg, cfg.generatorName, resolved.GeneratorConfig)
	if err != nil {
		return err
	}

	// Inject operator-supplied refusal phrases into the mitigation detectors so
	// a target's custom guardrail phrasing is recognized as a refusal (LAB-4664).
	yamlCfg = applyRefusalPatterns(yamlCfg, cfg.refusalPatterns)

	// Create detectors
	detectorList, err := createDetectors(cfg.detectorNames, probeList, yamlCfg)
	if err != nil {
		return err
	}

	// Build per-probe detector overrides for probes with detector_config blocks.
	// Called before buff wrapping so that the raw probes' ProbeDetectorConfig
	// interface is accessible; BuffedProber wrappers do not forward the interface.
	probeDetectorOverrides, err := buildProbeDetectorMap(probeList, detectorList, yamlCfg)
	if err != nil {
		return fmt.Errorf("building per-probe detector map: %w", err)
	}

	// Create and apply buffs
	buffNames := cfg.buffNames
	if len(buffNames) == 0 && yamlCfg != nil && len(yamlCfg.Buffs.Names) > 0 {
		buffNames = yamlCfg.Buffs.Names
	}
	probeList, err = createAndApplyBuffs(probeList, buffNames, yamlCfg)
	if err != nil {
		return err
	}

	// Create harness with resolved scanner options
	harnessConfig := registry.Config{
		"scanner_opts": &resolved.ScannerOpts,
		"concurrency":  resolved.ScannerOpts.Concurrency,
		"timeout":      resolved.ScannerOpts.Timeout,
	}
	if onAttemptProcessed != nil {
		harnessConfig["on_attempt_processed"] = onAttemptProcessed
	}
	if len(probeDetectorOverrides) > 0 {
		harnessConfig["probe_detector_overrides"] = probeDetectorOverrides
	}
	harness, err := harnesses.Create(cfg.harnessName, harnessConfig)
	if err != nil {
		return fmt.Errorf("failed to create harness %s: %w", cfg.harnessName, err)
	}

	// Run the scan
	scanErr := harness.Run(ctx, gen, probeList, detectorList, eval)

	// Runtime hooks: run cleanup hook after scan
	if cfg.cleanup != "" {
		slog.Info("running cleanup hook")
		cleanupHook := &hooks.Hook{Command: cfg.cleanup}
		cleanupEnv := map[string]string{
			"AUGUSTUS_GENERATOR": cfg.generatorName,
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if _, cleanupErr := cleanupHook.Run(cleanupCtx, cleanupEnv); cleanupErr != nil {
			slog.Error("cleanup hook failed", "error", cleanupErr)
			scanErr = errors.Join(scanErr, fmt.Errorf("cleanup hook failed: %w", cleanupErr))
		}
	}

	return scanErr
}

type tableEvaluator struct {
	verbose bool
}

func (t *tableEvaluator) Evaluate(ctx context.Context, attempts []*attempt.Attempt) error {
	fmt.Println("\nAugustus Scan Results")
	fmt.Println("=====================")

	if len(attempts) == 0 {
		fmt.Println("No attempts recorded")
		return nil
	}

	type row struct {
		probe    string
		detector string
		passed   string
		score    string
		status   string
	}

	rows := make([]row, 0, len(attempts))
	totalPassed := 0
	totalFailed := 0

	for _, a := range attempts {
		scores := a.GetEffectiveScores()
		maxScore := 0.0
		for _, score := range scores {
			if score > maxScore {
				maxScore = score
			}
		}

		passed := maxScore <= attempt.DefaultVulnerabilityThreshold
		status := "SAFE"
		passedStr := "true"
		if !passed {
			status = "VULN"
			passedStr = "false"
			totalFailed++
		} else {
			totalPassed++
		}

		detector := a.Detector
		if detector == "" {
			detector = "-"
		}

		rows = append(rows, row{
			probe:    a.Probe,
			detector: detector,
			passed:   passedStr,
			score:    fmt.Sprintf("%.2f", maxScore),
			status:   status,
		})
	}

	headers := row{"PROBE", "DETECTOR", "PASSED", "SCORE", "STATUS"}
	widths := [5]int{len(headers.probe), len(headers.detector), len(headers.passed), len(headers.score), len(headers.status)}
	for _, r := range rows {
		cols := [5]string{r.probe, r.detector, r.passed, r.score, r.status}
		for i, col := range cols {
			if len(col) > widths[i] {
				widths[i] = len(col)
			}
		}
	}

	separator := fmt.Sprintf("+-%s-+-%s-+-%s-+-%s-+-%s-+",
		repeatDash(widths[0]), repeatDash(widths[1]), repeatDash(widths[2]),
		repeatDash(widths[3]), repeatDash(widths[4]))
	rowFmt := fmt.Sprintf("| %%-%ds | %%-%ds | %%-%ds | %%-%ds | %%-%ds |",
		widths[0], widths[1], widths[2], widths[3], widths[4])

	fmt.Println(separator)
	fmt.Println(fmt.Sprintf(rowFmt, headers.probe, headers.detector, headers.passed, headers.score, headers.status))
	fmt.Println(separator)
	for _, r := range rows {
		fmt.Println(fmt.Sprintf(rowFmt, r.probe, r.detector, r.passed, r.score, r.status))
	}
	fmt.Println(separator)

	if t.verbose {
		fmt.Println()
		for i, a := range attempts {
			scores := a.GetEffectiveScores()
			maxScore := 0.0
			for _, score := range scores {
				if score > maxScore {
					maxScore = score
				}
			}
			status := "PASS"
			if maxScore > attempt.DefaultVulnerabilityThreshold {
				status = "FAIL"
			}

			// Check for multi-turn attack metadata
			if attackType, ok := a.Metadata["attack_type"].(string); ok {
				totalTurns := 0
				if tt, ok := a.Metadata["total_turns"].(int); ok {
					totalTurns = tt
				}
				goal := ""
				if g, ok := a.Metadata["goal"].(string); ok {
					goal = g
				}

				// Capitalize first letter of attack type
				attackLabel := strings.ToUpper(attackType[:1]) + attackType[1:]

				if t.verbose {
					fmt.Printf("  %s Attack (%d turns) - %s (score: %.2f)\n", attackLabel, totalTurns, status, maxScore)
					if goal != "" {
						fmt.Printf("  Goal: %q\n\n", goal)
					}

					// Extract turn data — handle both in-memory []TurnRecord and JSON-deserialized []any
					type turnInfo struct {
						turnNum    int
						question   string
						response   string
						score      float64
						wasRefused bool
					}
					var turns []turnInfo

					switch records := a.Metadata["turn_records"].(type) {
					case []any:
						for _, r := range records {
							if rec, ok := r.(map[string]any); ok {
								ti := turnInfo{}
								if v, ok := rec["turn_number"].(float64); ok {
									ti.turnNum = int(v)
								}
								if v, ok := rec["turn_number"].(int); ok {
									ti.turnNum = v
								}
								ti.question, _ = rec["question"].(string)
								ti.response, _ = rec["response"].(string)
								if v, ok := rec["judge_score"].(float64); ok {
									ti.score = v
								}
								ti.wasRefused, _ = rec["was_refused"].(bool)
								turns = append(turns, ti)
							}
						}
					default:
						// In-memory type (e.g. []TurnRecord) — marshal/unmarshal to normalize
						if records != nil {
							jsonBytes, jsonErr := json.Marshal(records)
							if jsonErr == nil {
								var rawTurns []map[string]any
								if json.Unmarshal(jsonBytes, &rawTurns) == nil {
									for _, rec := range rawTurns {
										ti := turnInfo{}
										if v, ok := rec["turn_number"].(float64); ok {
											ti.turnNum = int(v)
										}
										ti.question, _ = rec["question"].(string)
										ti.response, _ = rec["response"].(string)
										if v, ok := rec["judge_score"].(float64); ok {
											ti.score = v
										}
										ti.wasRefused, _ = rec["was_refused"].(bool)
										turns = append(turns, ti)
									}
								}
							}
						}
					}

					for _, ti := range turns {
						successMarker := ""
						if ti.score >= 0.8 {
							successMarker = "  [SUCCESS]"
						}
						refusedMarker := ""
						if ti.wasRefused {
							refusedMarker = "  [REFUSED]"
						}

						w := terminalWidth()
						fmt.Printf("  │  Turn %d%s%s  (score: %.2f)\n", ti.turnNum, successMarker, refusedMarker, ti.score)
						fmt.Println("  │  Attacker:")
						fmt.Println(wordWrap(ti.question, "  │    ", w))
						fmt.Println("  │  Target:")
						fmt.Println(wordWrap(ti.response, "  │    ", w))
						fmt.Println("  │")
					}
				} else {
					fmt.Printf("  %s Attack (%d turns) - %s (score: %.2f)\n", attackLabel, totalTurns, status, maxScore)
				}
			} else if t.verbose {
				w := terminalWidth()
				statusIcon := "✓"
				if status == "FAIL" {
					statusIcon = "✗"
				}
				fmt.Printf("  ┌─ Attempt %d: %s %s (score: %.2f)\n", i+1, statusIcon, status, maxScore)
				fmt.Printf("  │  Probe: %s\n", a.Probe)
				if len(a.Prompts) > 0 {
					fmt.Println("  │  Prompt:")
					fmt.Println(wordWrap(a.Prompts[0], "  │    ", w))
				}
				if len(a.Outputs) > 0 {
					fmt.Println("  │  Response:")
					fmt.Println(wordWrap(a.Outputs[0], "  │    ", w))
				}
				fmt.Printf("  └%s\n", strings.Repeat("─", 50))
			}
		}
	}

	fmt.Printf("\nOverall: %d passed, %d failed (total: %d)\n", totalPassed, totalFailed, len(attempts))
	return nil
}

func repeatDash(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '-'
	}
	return string(b)
}

// jsonEvaluator prints results in JSON format.
type jsonEvaluator struct{}

func (j *jsonEvaluator) Evaluate(ctx context.Context, attempts []*attempt.Attempt) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(map[string]any{
		"attempts": attempts,
		"count":    len(attempts),
	})
}

// jsonlEvaluator prints results in JSONL format (one JSON object per line).
type jsonlEvaluator struct{}

func (j *jsonlEvaluator) Evaluate(ctx context.Context, attempts []*attempt.Attempt) error {
	// Convert to simplified format and write each as JSON line
	resultList := results.ToAttemptResults(attempts)
	encoder := json.NewEncoder(os.Stdout)
	for _, result := range resultList {
		if err := encoder.Encode(result); err != nil {
			return fmt.Errorf("failed to encode result: %w", err)
		}
	}
	return nil
}

// collectingEvaluator wraps another evaluator and collects attempts for file output.
type collectingEvaluator struct {
	inner     harnesses.Evaluator
	attempts  []*attempt.Attempt
	jsonlPath string
	htmlPath  string
}

func (c *collectingEvaluator) Evaluate(ctx context.Context, attempts []*attempt.Attempt) error {
	// Store attempts for file output
	c.attempts = attempts

	// Call inner evaluator for stdout display
	if err := c.inner.Evaluate(ctx, attempts); err != nil {
		return err
	}

	// Write JSONL file if path specified
	if c.jsonlPath != "" {
		if err := results.WriteJSONL(c.jsonlPath, attempts); err != nil {
			return fmt.Errorf("failed to write JSONL output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "\nJSONL output written to: %s\n", c.jsonlPath)
	}

	// Write HTML file if path specified
	if c.htmlPath != "" {
		if err := results.WriteHTML(c.htmlPath, attempts); err != nil {
			return fmt.Errorf("failed to write HTML report: %w", err)
		}
		fmt.Fprintf(os.Stderr, "\nHTML report written to: %s\n", c.htmlPath)
	}

	return nil
}

// wordWrap wraps text to the given width, prefixing each line with the given prefix.
func wordWrap(text, prefix string, width int) string {
	// Replace newlines with spaces for uniform wrapping
	text = strings.ReplaceAll(text, "\n", " ")
	text = strings.TrimSpace(text)

	maxLine := width - len(prefix)
	if maxLine < 20 {
		maxLine = 20
	}

	runes := []rune(text)
	var lines []string
	for len(runes) > 0 {
		if len(runes) <= maxLine {
			lines = append(lines, prefix+string(runes))
			break
		}
		// Find last space within maxLine
		cut := maxLine
		for cut > 0 && runes[cut] != ' ' {
			cut--
		}
		if cut == 0 {
			cut = maxLine // No space found, hard break
		}
		lines = append(lines, prefix+string(runes[:cut]))
		runes = []rune(strings.TrimSpace(string(runes[cut:])))
	}
	return strings.Join(lines, "\n")
}

// terminalWidth returns the terminal width, defaulting to 90 columns.
func terminalWidth() int {
	const fallback = 90
	if cols, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && cols > 0 {
		return cols
	}
	return fallback
}
