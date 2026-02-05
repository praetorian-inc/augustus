// Package donotanswer provides probes from the Do-Not-Answer dataset.
//
// Do-Not-Answer is an open-source dataset to evaluate LLMs' safety mechanism at a low cost.
// The dataset consists of prompts to which language models are often trained not to answer.
//
// The DNA tests are somewhat opinionated and don't represent universal norms (nothing does), so use with care.
//
// Further info:
// * https://github.com/Libr-AI/do-not-answer
// * https://arxiv.org/abs/2308.13387
//
// Python garak equivalent: garak.probes.donotanswer
package donotanswer

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Embedded data files
//
//go:embed data/discrimination_exclusion_toxicity_hateful_offensive.txt
var discriminationData []byte

//go:embed data/human_chatbox.txt
var humanChatboxData []byte

//go:embed data/information_hazard.txt
var informationHazardData []byte

//go:embed data/malicious_uses.txt
var maliciousUsesData []byte

//go:embed data/misinformation_harms.txt
var misinformationHarmsData []byte

func init() {
	probes.Register("donotanswer.DiscriminationExclusionToxicityHatefulOffensive", NewDiscriminationExclusionToxicityHatefulOffensive)
	probes.Register("donotanswer.HumanChatbox", NewHumanChatbox)
	probes.Register("donotanswer.InformationHazard", NewInformationHazard)
	probes.Register("donotanswer.MaliciousUses", NewMaliciousUses)
	probes.Register("donotanswer.MisinformationHarms", NewMisinformationHarms)
}

// loadPrompts parses text data (one prompt per line) into a string slice.
func loadPrompts(data []byte) ([]string, error) {
	var prompts []string
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		prompts = append(prompts, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return prompts, nil
}

// baseProbe provides common functionality for all DoNotAnswer probes.
type baseProbe struct {
	name            string
	description     string
	goal            string
	primaryDetector string
	prompts         []string
}

func (b *baseProbe) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	attempts := make([]*attempt.Attempt, 0, len(b.prompts))

	for _, prompt := range b.prompts {
		conv := attempt.NewConversation()
		conv.AddPrompt(prompt)

		responses, err := gen.Generate(ctx, conv, 1)

		a := attempt.New(prompt)
		a.Probe = b.name
		a.Detector = b.primaryDetector

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

func (b *baseProbe) Name() string               { return b.name }
func (b *baseProbe) Description() string        { return b.description }
func (b *baseProbe) Goal() string               { return b.goal }
func (b *baseProbe) GetPrimaryDetector() string { return b.primaryDetector }
func (b *baseProbe) GetPrompts() []string       { return b.prompts }

// ----------------------------------------------------------------------------
// DiscriminationExclusionToxicityHatefulOffensive - Testing discrimination and toxicity
// ----------------------------------------------------------------------------

// DiscriminationExclusionToxicityHatefulOffensive tests with prompts from the
// discrimination, exclusion, toxicity, hateful, and offensive category.
//
// This probe poses prompts whose response should be refused by the model
// due to discriminatory or toxic content.
type DiscriminationExclusionToxicityHatefulOffensive struct {
	baseProbe
}

// NewDiscriminationExclusionToxicityHatefulOffensive creates a probe with discrimination/toxicity prompts.
func NewDiscriminationExclusionToxicityHatefulOffensive(_ registry.Config) (probes.Prober, error) {
	prompts, err := loadPrompts(discriminationData)
	if err != nil {
		return nil, err
	}

	return &DiscriminationExclusionToxicityHatefulOffensive{
		baseProbe: baseProbe{
			name:            "donotanswer.DiscriminationExclusionToxicityHatefulOffensive",
			description:     "Implementation of discrimination_exclusion_toxicity_hateful_offensive probes in DoNotAnswer_Prompts",
			goal:            "get model to respond as discrimination exclusion toxicity hateful offensive",
			primaryDetector: "mitigation.MitigationBypass",
			prompts:         prompts,
		},
	}, nil
}

// ----------------------------------------------------------------------------
// HumanChatbox - Testing human impersonation
// ----------------------------------------------------------------------------

// HumanChatbox tests with prompts from the human chatbox category.
//
// This probe poses prompts whose response should be refused by the model
// due to attempts to impersonate humans or bypass AI restrictions.
type HumanChatbox struct {
	baseProbe
}

// NewHumanChatbox creates a probe with human chatbox prompts.
func NewHumanChatbox(_ registry.Config) (probes.Prober, error) {
	prompts, err := loadPrompts(humanChatboxData)
	if err != nil {
		return nil, err
	}

	return &HumanChatbox{
		baseProbe: baseProbe{
			name:            "donotanswer.HumanChatbox",
			description:     "Implementation of human chatbox probes in DoNotAnswer_Prompts",
			goal:            "get model to respond as human chatbox",
			primaryDetector: "mitigation.MitigationBypass",
			prompts:         prompts,
		},
	}, nil
}

// ----------------------------------------------------------------------------
// InformationHazard - Testing information hazards
// ----------------------------------------------------------------------------

// InformationHazard tests with prompts from the information hazard category.
//
// This probe poses prompts whose response should be refused by the model
// due to containing dangerous or hazardous information.
type InformationHazard struct {
	baseProbe
}

// NewInformationHazard creates a probe with information hazard prompts.
func NewInformationHazard(_ registry.Config) (probes.Prober, error) {
	prompts, err := loadPrompts(informationHazardData)
	if err != nil {
		return nil, err
	}

	return &InformationHazard{
		baseProbe: baseProbe{
			name:            "donotanswer.InformationHazard",
			description:     "Implementation of information hazard probes in DoNotAnswer_Prompts",
			goal:            "get model to respond as information hazard",
			primaryDetector: "mitigation.MitigationBypass",
			prompts:         prompts,
		},
	}, nil
}

// ----------------------------------------------------------------------------
// MaliciousUses - Testing malicious use cases
// ----------------------------------------------------------------------------

// MaliciousUses tests with prompts from the malicious uses category.
//
// This probe poses prompts whose response should be refused by the model
// due to facilitating malicious activities.
type MaliciousUses struct {
	baseProbe
}

// NewMaliciousUses creates a probe with malicious uses prompts.
func NewMaliciousUses(_ registry.Config) (probes.Prober, error) {
	prompts, err := loadPrompts(maliciousUsesData)
	if err != nil {
		return nil, err
	}

	return &MaliciousUses{
		baseProbe: baseProbe{
			name:            "donotanswer.MaliciousUses",
			description:     "Implementation of malicious uses probes in DoNotAnswer_Prompts",
			goal:            "get model to respond as malicious uses",
			primaryDetector: "mitigation.MitigationBypass",
			prompts:         prompts,
		},
	}, nil
}

// ----------------------------------------------------------------------------
// MisinformationHarms - Testing misinformation
// ----------------------------------------------------------------------------

// MisinformationHarms tests with prompts from the misinformation harms category.
//
// This probe poses prompts whose response should be refused by the model
// due to potential spread of misinformation.
type MisinformationHarms struct {
	baseProbe
}

// NewMisinformationHarms creates a probe with misinformation harms prompts.
func NewMisinformationHarms(_ registry.Config) (probes.Prober, error) {
	prompts, err := loadPrompts(misinformationHarmsData)
	if err != nil {
		return nil, err
	}

	return &MisinformationHarms{
		baseProbe: baseProbe{
			name:            "donotanswer.MisinformationHarms",
			description:     "Implementation of misinformation_harms probes in DoNotAnswer_Prompts",
			goal:            "get model to respond as misinformation harms",
			primaryDetector: "mitigation.MitigationBypass",
			prompts:         prompts,
		},
	}, nil
}
