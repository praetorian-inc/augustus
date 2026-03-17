package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	ctxprobe "github.com/praetorian-inc/augustus/internal/probes/context"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// ExtractContextCmd extracts system context from a target LLM.
type ExtractContextCmd struct {
	Generator     string        `arg:"" help:"Generator name (e.g., openai.OpenAI)." required:""`
	Config        string        `help:"JSON config for generator/probe." short:"c"`
	Model         string        `help:"Model name for target generator." short:"m"`
	AttackerModel string        `help:"Model name for attacker LLM." name:"attacker-model"`
	JudgeModel    string        `help:"Model name for judge LLM." name:"judge-model"`
	MaxTurns      int           `help:"Maximum conversation turns (default: 10)." name:"max-turns" default:"0"`
	Goal          string        `help:"Custom extraction goal." name:"goal"`
	Output        string        `help:"Output YAML file path." short:"o" required:"" type:"path"`
	Verbose       bool          `help:"Verbose output." short:"v"`
	Timeout       time.Duration `help:"Overall timeout (0 = no timeout)."`
}

func (e *ExtractContextCmd) Run() error {
	// Build probe config from flags
	cfg := make(registry.Config)

	// Parse --config JSON if provided
	if e.Config != "" {
		var cfgMap map[string]any
		if err := json.Unmarshal([]byte(e.Config), &cfgMap); err != nil {
			return fmt.Errorf("invalid --config JSON: %w", err)
		}
		for k, v := range cfgMap {
			cfg[k] = v
		}
	}

	// Set target generator type for probe's attacker/judge generator creation
	cfg["target_generator_type"] = e.Generator

	// Apply model flags (override --config values)
	if e.Model != "" {
		cfg["model"] = e.Model
	}
	if e.AttackerModel != "" {
		cfg["attacker_model"] = e.AttackerModel
	}
	if e.JudgeModel != "" {
		cfg["judge_model"] = e.JudgeModel
	}
	if e.MaxTurns > 0 {
		cfg["max_turns"] = e.MaxTurns
	}
	if e.Goal != "" {
		cfg["goal"] = e.Goal
	}

	// Create the probe
	prober, err := probes.Create("context.SystemContext", cfg)
	if err != nil {
		return fmt.Errorf("failed to create context probe: %w", err)
	}

	probe, ok := prober.(*ctxprobe.SystemContextProbe)
	if !ok {
		return fmt.Errorf("internal error: context.SystemContext probe has unexpected type %T", prober)
	}

	// Create target generator
	genCfg := make(registry.Config)
	if e.Model != "" {
		genCfg["model"] = e.Model
	}
	// Merge any generator-specific config from --config
	if e.Config != "" {
		var cfgMap map[string]any
		if err := json.Unmarshal([]byte(e.Config), &cfgMap); err == nil {
			for k, v := range cfgMap {
				genCfg[k] = v
			}
		}
	}

	gen, err := generators.Create(e.Generator, genCfg)
	if err != nil {
		return fmt.Errorf("failed to create generator %s: %w", e.Generator, err)
	}

	// Setup context with timeout and signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if e.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, e.Timeout)
		defer cancel()
	}

	// Run the probe
	if e.Verbose {
		fmt.Printf("Extracting context from %s...\n", e.Generator)
	}

	_, err = probe.Probe(ctx, gen)
	if err != nil {
		return fmt.Errorf("context extraction failed: %w", err)
	}

	// Get extracted context
	ec := probe.ExtractedContext()
	if ec == nil {
		return fmt.Errorf("no context was extracted")
	}

	// Validate
	if err := ec.Validate(); err != nil {
		// Write anyway but warn
		fmt.Fprintf(os.Stderr, "Warning: extracted context is incomplete: %v\n", err)
	}

	// Write YAML output
	if err := ctxprobe.WriteExtractedContext(e.Output, ec); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	// Print summary
	fmt.Printf("\nContext extracted to: %s\n", e.Output)
	fmt.Printf("Confidence: %.0f%%\n", ec.Confidence*100)
	if ec.SystemPrompt != "" {
		fmt.Printf("System prompt: %s\n", truncate(ec.SystemPrompt, 80))
	}
	if len(ec.Tools) > 0 {
		fmt.Printf("Tools discovered: %d\n", len(ec.Tools))
		for _, t := range ec.Tools {
			fmt.Printf("  - %s\n", t.Name)
		}
	}
	if ec.Identity.UserID != "" || ec.Identity.Tenant != "" || ec.Identity.Role != "" {
		fmt.Printf("Identity: user=%s tenant=%s role=%s\n",
			ec.Identity.UserID, ec.Identity.Tenant, ec.Identity.Role)
	}
	if len(ec.Identity.Permissions) > 0 {
		fmt.Printf("Permissions: %d discovered\n", len(ec.Identity.Permissions))
	}

	return nil
}
