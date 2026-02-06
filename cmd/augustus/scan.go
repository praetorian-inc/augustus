package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/results"
	"github.com/praetorian-inc/augustus/pkg/scanner"
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
	outputFile    string        // JSONL output file path
	htmlFile      string        // HTML report file path
	verbose       bool
	allProbes     bool          // Run all registered probes
	timeout       time.Duration // Overall scan timeout
	concurrency   int           // Max concurrent probes
	probeTimeout  time.Duration // Per-probe timeout
}

// Kong helper methods

func (s *ScanCmd) execute() error {
	cfg := s.loadScanConfig()

	if err := s.expandGlobPatterns(cfg); err != nil {
		return err
	}

	eval := s.createEvaluator(cfg)
	ctx, cancel := s.setupContext()
	defer cancel()

	return runScan(ctx, cfg, eval)
}

// loadScanConfig converts Kong struct to legacy scanConfig
func (s *ScanCmd) loadScanConfig() *scanConfig {
	return &scanConfig{
		generatorName: s.Generator,
		probeNames:    s.Probe,
		detectorNames: s.Detectors,
		buffNames:     s.Buff,
		harnessName:   s.Harness,
		configFile:    s.ConfigFile,
		configJSON:    s.Config,
		outputFormat:  s.Format,
		outputFile:    s.Output,
		htmlFile:      s.HTML,
		verbose:       s.Verbose,
		allProbes:     s.All,
		timeout:       s.Timeout,
		concurrency:   s.Concurrency,
		probeTimeout:  s.ProbeTimeout,
	}
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

// setupContext creates context with timeout and signal handling.
// The returned cancel func MUST be called to avoid leaking timers/resources.
func (s *ScanCmd) setupContext() (context.Context, context.CancelFunc) {
	baseCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithTimeout(baseCtx, s.Timeout)
	return ctx, func() {
		stop()
		cancel()
	}
}

// runScan executes the scan with the given configuration.
func runScan(ctx context.Context, cfg *scanConfig, eval harnesses.Evaluator) error {
	// Parse generator config
	var genConfig registry.Config
	var scannerOpts *scanner.Options
	var yamlCfg *config.Config

	// Load from YAML file if provided
	if cfg.configFile != "" {
		var err error
		yamlCfg, err = config.LoadConfig(cfg.configFile)
		if err != nil {
			return fmt.Errorf("failed to load config file: %w", err)
		}

		// Extract generator config for the specified generator
		generatorCfg, exists := yamlCfg.Generators[cfg.generatorName]
		if !exists {
			return fmt.Errorf("generator %q not found in config file", cfg.generatorName)
		}

		// Convert GeneratorConfig to registry.Config (map[string]any)
		genConfig = registry.Config{
			"model":       generatorCfg.Model,
			"temperature": generatorCfg.Temperature,
			"api_key":     generatorCfg.APIKey,
			"rate_limit":  generatorCfg.RateLimit,
		}
	} else if cfg.configJSON != "" {
		// Fall back to JSON config
		if err := json.Unmarshal([]byte(cfg.configJSON), &genConfig); err != nil {
			return fmt.Errorf("invalid config JSON: %w", err)
		}
	} else {
		genConfig = registry.Config{}
	}

	// Wire up remaining config sections
	if yamlCfg != nil {
		scannerOpts = &scanner.Options{
			Concurrency:  10,              // default
			ProbeTimeout: 5 * time.Minute, // default
			RetryCount:   0,
			RetryBackoff: 1 * time.Second,
		}

		// Wire Run config
		if yamlCfg.Run.Timeout != "" {
			timeout, err := time.ParseDuration(yamlCfg.Run.Timeout)
			if err != nil {
				return fmt.Errorf("invalid run.timeout: %w", err)
			}
			scannerOpts.Timeout = timeout
		} else {
			scannerOpts.Timeout = 30 * time.Minute
		}

		// Wire Run.Concurrency from YAML
		if yamlCfg.Run.Concurrency > 0 {
			scannerOpts.Concurrency = yamlCfg.Run.Concurrency
		}

		// Wire Run.ProbeTimeout from YAML
		if yamlCfg.Run.ProbeTimeout != "" {
			probeTimeout, err := time.ParseDuration(yamlCfg.Run.ProbeTimeout)
			if err != nil {
				return fmt.Errorf("invalid run.probe_timeout: %w", err)
			}
			scannerOpts.ProbeTimeout = probeTimeout
		}

		if yamlCfg.Run.MaxAttempts > 0 {
			scannerOpts.RetryCount = yamlCfg.Run.MaxAttempts
		}

		// Wire Output config (as defaults, CLI flags override)
		if cfg.outputFormat == "" && yamlCfg.Output.Format != "" {
			cfg.outputFormat = yamlCfg.Output.Format
		}
		if cfg.outputFile == "" && yamlCfg.Output.Path != "" {
			cfg.outputFile = yamlCfg.Output.Path
		}
	}

	// CLI flags override YAML config
	if cfg.concurrency > 0 {
		if scannerOpts == nil {
			scannerOpts = &scanner.Options{
				Concurrency:  cfg.concurrency,
				ProbeTimeout: cfg.probeTimeout,
				Timeout:      cfg.timeout,
				RetryCount:   0,
				RetryBackoff: 1 * time.Second,
			}
		} else {
			scannerOpts.Concurrency = cfg.concurrency
		}
	}

	if cfg.probeTimeout > 0 {
		if scannerOpts == nil {
			scannerOpts = &scanner.Options{
				Concurrency:  10,
				ProbeTimeout: cfg.probeTimeout,
				Timeout:      cfg.timeout,
				RetryCount:   0,
				RetryBackoff: 1 * time.Second,
			}
		} else {
			scannerOpts.ProbeTimeout = cfg.probeTimeout
		}
	}

	// Ensure scannerOpts exists even if no config provided
	// Start with defaults, then override with CLI flags if set
	if scannerOpts == nil {
		defaults := scanner.DefaultOptions()
		scannerOpts = &defaults
		// Override with CLI flags only if explicitly set (non-zero)
		if cfg.concurrency > 0 {
			scannerOpts.Concurrency = cfg.concurrency
		}
		if cfg.probeTimeout > 0 {
			scannerOpts.ProbeTimeout = cfg.probeTimeout
		}
		if cfg.timeout > 0 {
			scannerOpts.Timeout = cfg.timeout
		}
	}

	// Create generator
	gen, err := generators.Create(cfg.generatorName, genConfig)
	if err != nil {
		return fmt.Errorf("failed to create generator %s: %w", cfg.generatorName, err)
	}

	// Get probe names (either from --all or specific flags)
	probeNames := cfg.probeNames
	if cfg.allProbes {
		probeNames = probes.List()
		fmt.Printf("Running all %d registered probes\n", len(probeNames))
	}

	// Create probes
	probeList := make([]probes.Prober, 0, len(probeNames))
	for _, probeName := range probeNames {
		probe, err := probes.Create(probeName, registry.Config{})
		if err != nil {
			return fmt.Errorf("failed to create probe %s: %w", probeName, err)
		}
		probeList = append(probeList, probe)
	}

	// Create detectors (use probe's primary detector if none specified)
	var detectorList []detectors.Detector
	if len(cfg.detectorNames) > 0 {
		detectorList = make([]detectors.Detector, 0, len(cfg.detectorNames))
		for _, detectorName := range cfg.detectorNames {
			detector, err := detectors.Create(detectorName, registry.Config{})
			if err != nil {
				return fmt.Errorf("failed to create detector %s: %w", detectorName, err)
			}
			detectorList = append(detectorList, detector)
		}
	} else {
		// Collect unique primary detectors from ALL probes
		uniqueDetectors := make(map[string]struct{})
		for _, probe := range probeList {
			uniqueDetectors[probe.GetPrimaryDetector()] = struct{}{}
		}

		for detectorName := range uniqueDetectors {
			detector, err := detectors.Create(detectorName, registry.Config{})
			if err != nil {
				return fmt.Errorf("failed to create detector %s: %w", detectorName, err)
			}
			detectorList = append(detectorList, detector)
		}

		if len(detectorList) == 0 {
			return errors.New("no detectors available")
		}
	}

	// Create buffs (if configured)
	var buffChain *buffs.BuffChain
	// Get buff names from CLI or YAML config
	buffNames := cfg.buffNames
	if len(buffNames) == 0 && yamlCfg != nil && len(yamlCfg.Buffs.Names) > 0 {
		buffNames = yamlCfg.Buffs.Names
	}

	if len(buffNames) > 0 {
		buffList := make([]buffs.Buff, 0, len(buffNames))
		for _, buffName := range buffNames {
			// Get per-buff settings from YAML config if available
			buffCfg := registry.Config{}
			if yamlCfg != nil && yamlCfg.Buffs.Settings != nil {
				if settings, ok := yamlCfg.Buffs.Settings[buffName]; ok {
					for k, v := range settings {
						buffCfg[k] = v
					}
				}
			}

			buff, err := buffs.Create(buffName, buffCfg)
			if err != nil {
				return fmt.Errorf("failed to create buff %s: %w", buffName, err)
			}
			buffList = append(buffList, buff)
		}
		buffChain = buffs.NewBuffChain(buffList...)

		fmt.Printf("Using %d buff(s): ", len(buffList))
		for i, b := range buffList {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Print(b.Name())
		}
		fmt.Println()
	}

	// Wrap probes with buffs if configured
	if buffChain != nil && !buffChain.IsEmpty() {
		for i, probe := range probeList {
			probeList[i] = buffs.NewBuffedProber(probe, buffChain, gen)
		}
	}

	// Create harness
	harnessConfig := registry.Config{}
	if scannerOpts != nil {
		harnessConfig["scanner_opts"] = scannerOpts
		// Pass concurrency and timeout directly for harnesses that don't use scanner_opts
		harnessConfig["concurrency"] = scannerOpts.Concurrency
		harnessConfig["timeout"] = scannerOpts.Timeout
	}
	harness, err := harnesses.Create(cfg.harnessName, harnessConfig)
	if err != nil {
		return fmt.Errorf("failed to create harness %s: %w", cfg.harnessName, err)
	}

	// Run the scan
	return harness.Run(ctx, gen, probeList, detectorList, eval)
}

// Evaluator implementations

// tableEvaluator prints results in table format.
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

	// Group by probe
	probeAttempts := make(map[string][]*attempt.Attempt)
	for _, a := range attempts {
		probeAttempts[a.Probe] = append(probeAttempts[a.Probe], a)
	}

	// Print results by probe
	totalPassed := 0
	totalFailed := 0

	for probeName, attempts := range probeAttempts {
		fmt.Printf("\nProbe: %s\n", probeName)
		fmt.Println("---")

		passed := 0
		failed := 0

		for i, a := range attempts {
			// Determine if attempt passed or failed based on scores
			maxScore := 0.0
			for _, scores := range a.DetectorResults {
				for _, score := range scores {
					if score > maxScore {
						maxScore = score
					}
				}
			}

			status := "PASS"
			if maxScore > 0.5 {
				status = "FAIL"
				failed++
			} else {
				passed++
			}

			if t.verbose {
				fmt.Printf("  Attempt %d: %s (score: %.2f)\n", i+1, status, maxScore)
				if len(a.Prompts) > 0 {
					fmt.Printf("    Prompt: %s\n", truncate(a.Prompts[0], 60))
				}
				if len(a.Outputs) > 0 {
					fmt.Printf("    Response: %s\n", truncate(a.Outputs[0], 60))
				}
			}
		}

		fmt.Printf("  Summary: %d/%d attempts passed\n", passed, len(attempts))
		totalPassed += passed
		totalFailed += failed
	}

	fmt.Printf("\nOverall: %d passed, %d failed (total: %d)\n", totalPassed, totalFailed, len(attempts))
	return nil
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
