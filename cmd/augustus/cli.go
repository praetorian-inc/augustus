package main

import (
	"fmt"
	"time"

	"github.com/alecthomas/kong"
)

// CLI represents the Augustus command-line interface.
var CLI struct {
	// Global flags
	Debug      bool          `help:"Enable debug mode." short:"d" env:"AUGUSTUS_DEBUG"`
	Version    VersionCmd    `cmd:"" help:"Print version information."`
	Help       HelpCmd       `cmd:"" hidden:"" default:"1"`
	List       ListCmd       `cmd:"" help:"List available probes, detectors, generators."`
	Scan       ScanCmd       `cmd:"" help:"Run vulnerability scan against LLM."`
	Completion CompletionCmd `cmd:"" help:"Generate shell completion scripts."`
}

// VersionCmd prints version information.
type VersionCmd struct{}

func (v *VersionCmd) Run() error {
	printVersion()
	return nil
}

// HelpCmd prints help.
type HelpCmd struct{}

func (h *HelpCmd) Run(ctx *kong.Context) error {
	// Print top-level help (application help), not help for the implicit Help command.
	//
	// Note: Kong's Model.Help is the *description* (set via kong.Description),
	// not the rendered help text. Use PrintUsage to render full help.
	appCtx := *ctx
	if len(appCtx.Path) > 1 {
		appCtx.Path = appCtx.Path[:1]
	}
	return appCtx.PrintUsage(false)
}

// ListCmd lists available capabilities.
type ListCmd struct{}

func (l *ListCmd) Run() error {
	listCapabilities()
	return nil
}

// ScanCmd runs vulnerability scan against LLM.
type ScanCmd struct {
	// Required
	Generator string `arg:"" help:"Generator name (e.g., openai.OpenAI, anthropic.Anthropic)." required:""`

	// Probe selection (mutually exclusive groups)
	Probe      []string `help:"Probe names (repeatable)." short:"p" name:"probe" group:"probes" xor:"probe-selection"`
	ProbesGlob string   `help:"Comma-separated probe glob patterns (e.g., 'dan.*,encoding.*')." name:"probes-glob" group:"probes" xor:"probe-selection"`
	All        bool     `help:"Run all registered probes." group:"probes" xor:"probe-selection"`

	// Detector selection
	Detectors     []string `help:"Detector names (repeatable)." name:"detector"`
	DetectorsGlob string   `help:"Comma-separated detector glob patterns." name:"detectors-glob"`

	// Buff selection
	Buff      []string `help:"Buff names to apply (repeatable)." short:"b" name:"buff"`
	BuffsGlob string   `help:"Comma-separated buff glob patterns (e.g., 'encoding.*')." name:"buffs-glob"`

	// Configuration
	ConfigFile string `help:"YAML config file path." type:"existingfile" name:"config-file"`
	Config     string `help:"JSON config for generator." short:"c"`

	// Execution
	Harness      string        `help:"Harness name." default:"probewise.Probewise"`
	Timeout      time.Duration `help:"Overall scan timeout." default:"30m"`
	Concurrency  int           `help:"Max concurrent probes." default:"10" env:"AUGUSTUS_CONCURRENCY"`
	ProbeTimeout time.Duration `help:"Per-probe timeout." default:"5m"`

	// Output
	Format  string `help:"Output format." enum:"table,json,jsonl" default:"table" short:"f"`
	Output  string `help:"JSONL output file path." short:"o" type:"path"`
	HTML    string `help:"HTML report file path." type:"path" name:"html"`
	Verbose bool   `help:"Verbose output." short:"v"`
}

func (s *ScanCmd) Run() error {
	return s.execute()
}

func (s *ScanCmd) Validate() error {
	// Generator argument is required.
	if s.Generator == "" {
		return fmt.Errorf("generator argument is required")
	}

	// At least one probe selection method required
	if len(s.Probe) == 0 && s.ProbesGlob == "" && !s.All {
		return fmt.Errorf("at least one --probe, --probes-glob, or --all is required")
	}

	// Can't mix individual probes with glob/all
	if len(s.Probe) > 0 && (s.ProbesGlob != "" || s.All) {
		return fmt.Errorf("cannot use --probe with --probes-glob or --all")
	}

	// Can't use both config sources
	if s.ConfigFile != "" && s.Config != "" {
		return fmt.Errorf("cannot use both --config-file and --config")
	}

	return nil
}

// printVersion prints the version string.
func printVersion() {
	fmt.Printf("augustus %s\n", version)
}

// CompletionCmd generates shell completion scripts.
type CompletionCmd struct {
	Shell string `arg:"" enum:"bash,zsh,fish" help:"Shell type (bash, zsh, fish)."`
}

func (c *CompletionCmd) Run() error {
	switch c.Shell {
	case "bash":
		fmt.Println("# Bash completion for augustus")
		fmt.Println("# Add to ~/.bashrc:")
		fmt.Println("# eval \"$(augustus completion bash)\"")
	case "zsh":
		fmt.Println("# Zsh completion for augustus")
		fmt.Println("# Add to ~/.zshrc:")
		fmt.Println("# eval \"$(augustus completion zsh)\"")
	case "fish":
		fmt.Println("# Fish completion for augustus")
		fmt.Println("# Run: augustus completion fish | source")
	}
	return nil
}
