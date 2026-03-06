package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
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
	"github.com/praetorian-inc/augustus/pkg/parsers"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/results"
	"github.com/praetorian-inc/augustus/pkg/types"

	// Import parser implementations to register them
	_ "github.com/praetorian-inc/augustus/internal/parsers/external"
	_ "github.com/praetorian-inc/augustus/internal/parsers/json"
	_ "github.com/praetorian-inc/augustus/internal/parsers/passthrough"
	_ "github.com/praetorian-inc/augustus/internal/parsers/sse"
)

// scanConfig holds the configuration for a scan command.
type scanConfig struct {
	generatorName string
	probeNames    []string
	detectorNames []string
	buffNames     []string
	harnessName   string
	configFile    string // YAML config file path
	configJSON    string
	outputFormat  string
	outputFile    string // JSONL output file path
	htmlFile      string // HTML report file path
	verbose       bool
	allProbes     bool          // Run all registered probes
	timeout       time.Duration // Overall scan timeout
	concurrency   int           // Max concurrent probes
	probeTimeout  time.Duration // Per-probe timeout
	setup         string        // Shell command: once before all probes
	prepare       string        // Shell command: before each probe
	cleanup       string        // Shell command: after all probes

	// Parser configuration
	parserName         string // Parser name (e.g., "sse.Aggregate")
	parserConfig       string // Parser configuration as JSON
	allowUnsafeParsers bool   // Allow external parsers in unsafe mode
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
		defer streamWriter.Close()
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
		generatorName:      s.Generator,
		probeNames:         s.Probe,
		detectorNames:      s.Detectors,
		buffNames:          s.Buff,
		harnessName:        s.Harness,
		configFile:         s.ConfigFile,
		configJSON:         s.Config,
		outputFormat:       s.Format,
		outputFile:         s.Output,
		htmlFile:           s.HTML,
		verbose:            s.Verbose,
		allProbes:          s.All,
		timeout:            s.Timeout,
		concurrency:        s.Concurrency,
		probeTimeout:       s.ProbeTimeout,
		setup:              s.Setup,
		prepare:            s.Prepare,
		cleanup:            s.Cleanup,
		parserName:         s.Parser,
		parserConfig:       s.ParserConfig,
		allowUnsafeParsers: s.AllowUnsafeParsers,
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
func createProbes(probeNames []string, yamlCfg *config.Config) ([]probes.Prober, error) {
	probeList := make([]probes.Prober, 0, len(probeNames))
	for _, probeName := range probeNames {
		var probeCfg registry.Config
		if yamlCfg != nil {
			probeCfg = yamlCfg.ResolveProbeConfig(probeName)
		}
		probe, err := probes.Create(probeName, probeCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create probe %s: %w", probeName, err)
		}
		probeList = append(probeList, probe)
	}
	return probeList, nil
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
			}
			detector, err := detectors.Create(detectorName, detCfg)
			if err != nil {
				return nil, fmt.Errorf("failed to create detector %s: %w", detectorName, err)
			}
			detectorList = append(detectorList, detector)
		}
		if len(detectorList) == 0 {
			return nil, errors.New("no detectors available")
		}
	}

	return detectorList, nil
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

	// Wrap generator with parser if configured
	if cfg.parserName != "" {
		parserCfg := registry.Config{}
		if cfg.parserConfig != "" {
			if err := json.Unmarshal([]byte(cfg.parserConfig), &parserCfg); err != nil {
				return fmt.Errorf("invalid --parser-config JSON: %w", err)
			}
		}
		// Inject safety flag
		parserCfg["allow_unsafe"] = cfg.allowUnsafeParsers

		parser, err := parsers.Create(cfg.parserName, parserCfg)
		if err != nil {
			return fmt.Errorf("failed to create parser %s: %w", cfg.parserName, err)
		}
		gen = parsers.NewParsedGenerator(gen, parser)
		slog.Info("parser enabled", "parser", cfg.parserName)
	}

	// Get probe names
	probeNames := cfg.probeNames
	if cfg.allProbes {
		probeNames = probes.List()
		fmt.Printf("Running all %d registered probes\n", len(probeNames))
	}

	// Create probes
	probeList, err := createProbes(probeNames, yamlCfg)
	if err != nil {
		return err
	}

	// Create detectors
	detectorList, err := createDetectors(cfg.detectorNames, probeList, yamlCfg)
	if err != nil {
		return err
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
			fmt.Printf("  Attempt %d: %s (score: %.2f)\n", i+1, status, maxScore)
			if len(a.Prompts) > 0 {
				fmt.Printf("    Prompt: %s\n", truncate(a.Prompts[0], 60))
			}
			if len(a.Outputs) > 0 {
				fmt.Printf("    Response: %s\n", truncate(a.Outputs[0], 60))
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

// truncate shortens a string to maxLen, adding "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
