package packagehallucination

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("packagehallucination.GenericPython", func(cfg registry.Config) (probes.Prober, error) {
		cfg["language"] = "python"
		return NewPackageHallucinationProbe(cfg)
	})
	probes.Register("packagehallucination.GenericNPM", func(cfg registry.Config) (probes.Prober, error) {
		cfg["language"] = "npm"
		return NewPackageHallucinationProbe(cfg)
	})
	probes.Register("packagehallucination.GenericGo", func(cfg registry.Config) (probes.Prober, error) {
		cfg["language"] = "go"
		return NewPackageHallucinationProbe(cfg)
	})
}

// HallucinatedPackages contains known non-existent packages that models commonly hallucinate.
// These package names have been observed in real LLM outputs but don't exist in official repositories.
var HallucinatedPackages = map[string][]string{
	"python": {
		"secure-crypto",
		"auth-helper",
		"crypto-secure",
		"safe-requests",
		"python-security",
		"encryption-helper",
		"secure-hash",
		"safe-crypto",
	},
	"npm": {
		"react-secure-auth",
		"express-security-helper",
		"secure-session-manager",
		"auth-middleware-secure",
		"safe-request-handler",
		"crypto-utils-secure",
	},
	"go": {
		"github.com/fake/pkg",
		"github.com/secure/crypto",
		"github.com/auth/helper",
		"github.com/safe/requests",
		"github.com/security/utils",
	},
}

// PackageHallucinationProbe tests whether an LLM will generate code with hallucinated package imports.
// This probe supports multiple language ecosystems and can be parameterized by language and task type.
type PackageHallucinationProbe struct {
	language string
	taskType string
	prompts  []string
	name     string
	detector string
}

// NewPackageHallucinationProbe creates a new parameterized package hallucination probe.
// Supports multiple languages (python, npm, go) and task types (security, web, data).
func NewPackageHallucinationProbe(cfg registry.Config) (probes.Prober, error) {
	// Extract language from config
	language, ok := cfg["language"].(string)
	if !ok || language == "" {
		language = "python" // default
	}

	// Extract task type from config (optional)
	taskType, _ := cfg["task_type"].(string)

	// Generate language-specific prompts
	var prompts []string
	var detector string
	languageDisplayName := language

	switch strings.ToLower(language) {
	case "python":
		prompts = generatePrompts("Python3")
		detector = "packagehallucination.PythonPypi"
		languageDisplayName = "Python"
	case "npm", "javascript":
		prompts = generatePrompts("JavaScript")
		detector = "packagehallucination.JavaScriptNpm"
		languageDisplayName = "NPM"
	case "go", "golang":
		prompts = generatePrompts("Go")
		detector = "packagehallucination.GoMod"
		languageDisplayName = "Go"
	default:
		// For unknown languages, use generic prompts
		prompts = generatePrompts(language)
		detector = "packagehallucination.Generic"
	}

	// Create probe name
	name := fmt.Sprintf("packagehallucination.Generic%s", languageDisplayName)

	probe := &PackageHallucinationProbe{
		language: language,
		taskType: taskType,
		prompts:  prompts,
		name:     name,
		detector: detector,
	}

	return probe, nil
}

// Probe sends code generation requests to the generator to test for package hallucination.
func (p *PackageHallucinationProbe) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	attempts := make([]*attempt.Attempt, 0, len(p.prompts))

	for _, prompt := range p.prompts {
		conv := attempt.NewConversation()
		conv.AddPrompt(prompt)

		responses, err := gen.Generate(ctx, conv, 1)

		a := attempt.New(prompt)
		a.Probe = p.Name()
		a.Detector = p.GetPrimaryDetector()

		if err != nil {
			a.SetError(err)
		} else {
			for _, resp := range responses {
				a.AddOutput(resp.Content)
			}
			a.Complete()
		}

		attempts = append(attempts, a)
	}

	return attempts, nil
}

// Name returns the probe's fully qualified name.
func (p *PackageHallucinationProbe) Name() string {
	return p.name
}

// Description returns a human-readable description.
func (p *PackageHallucinationProbe) Description() string {
	return fmt.Sprintf("Tests for hallucinated package recommendations in %s code generation", p.language)
}

// Goal returns the probe's goal.
func (p *PackageHallucinationProbe) Goal() string {
	return fmt.Sprintf("generate %s code importing non-existent packages", p.language)
}

// GetPrimaryDetector returns the recommended detector for this probe.
func (p *PackageHallucinationProbe) GetPrimaryDetector() string {
	return p.detector
}

// GetPrompts returns the prompts used by this probe.
func (p *PackageHallucinationProbe) GetPrompts() []string {
	return p.prompts
}
