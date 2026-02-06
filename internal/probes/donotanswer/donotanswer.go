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
	_ "embed"

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

// ----------------------------------------------------------------------------
// DiscriminationExclusionToxicityHatefulOffensive - Testing discrimination and toxicity
// ----------------------------------------------------------------------------

// DiscriminationExclusionToxicityHatefulOffensive tests with prompts from the
// discrimination, exclusion, toxicity, hateful, and offensive category.
//
// This probe poses prompts whose response should be refused by the model
// due to discriminatory or toxic content.
type DiscriminationExclusionToxicityHatefulOffensive struct {
	*probes.SimpleProbe
}

// NewDiscriminationExclusionToxicityHatefulOffensive creates a probe with discrimination/toxicity prompts.
func NewDiscriminationExclusionToxicityHatefulOffensive(_ registry.Config) (probes.Prober, error) {
	promptList, err := probes.LoadLines(discriminationData)
	if err != nil {
		return nil, err
	}

	return &DiscriminationExclusionToxicityHatefulOffensive{
		SimpleProbe: &probes.SimpleProbe{
			ProbeName:        "donotanswer.DiscriminationExclusionToxicityHatefulOffensive",
			ProbeDescription: "Implementation of discrimination_exclusion_toxicity_hateful_offensive probes in DoNotAnswer_Prompts",
			ProbeGoal:        "get model to respond as discrimination exclusion toxicity hateful offensive",
			PrimaryDetector:  "mitigation.MitigationBypass",
			Prompts:          promptList,
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
	*probes.SimpleProbe
}

// NewHumanChatbox creates a probe with human chatbox prompts.
func NewHumanChatbox(_ registry.Config) (probes.Prober, error) {
	promptList, err := probes.LoadLines(humanChatboxData)
	if err != nil {
		return nil, err
	}

	return &HumanChatbox{
		SimpleProbe: &probes.SimpleProbe{
			ProbeName:        "donotanswer.HumanChatbox",
			ProbeDescription: "Implementation of human chatbox probes in DoNotAnswer_Prompts",
			ProbeGoal:        "get model to respond as human chatbox",
			PrimaryDetector:  "mitigation.MitigationBypass",
			Prompts:          promptList,
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
	*probes.SimpleProbe
}

// NewInformationHazard creates a probe with information hazard prompts.
func NewInformationHazard(_ registry.Config) (probes.Prober, error) {
	promptList, err := probes.LoadLines(informationHazardData)
	if err != nil {
		return nil, err
	}

	return &InformationHazard{
		SimpleProbe: &probes.SimpleProbe{
			ProbeName:        "donotanswer.InformationHazard",
			ProbeDescription: "Implementation of information hazard probes in DoNotAnswer_Prompts",
			ProbeGoal:        "get model to respond as information hazard",
			PrimaryDetector:  "mitigation.MitigationBypass",
			Prompts:          promptList,
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
	*probes.SimpleProbe
}

// NewMaliciousUses creates a probe with malicious uses prompts.
func NewMaliciousUses(_ registry.Config) (probes.Prober, error) {
	promptList, err := probes.LoadLines(maliciousUsesData)
	if err != nil {
		return nil, err
	}

	return &MaliciousUses{
		SimpleProbe: &probes.SimpleProbe{
			ProbeName:        "donotanswer.MaliciousUses",
			ProbeDescription: "Implementation of malicious uses probes in DoNotAnswer_Prompts",
			ProbeGoal:        "get model to respond as malicious uses",
			PrimaryDetector:  "mitigation.MitigationBypass",
			Prompts:          promptList,
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
	*probes.SimpleProbe
}

// NewMisinformationHarms creates a probe with misinformation harms prompts.
func NewMisinformationHarms(_ registry.Config) (probes.Prober, error) {
	promptList, err := probes.LoadLines(misinformationHarmsData)
	if err != nil {
		return nil, err
	}

	return &MisinformationHarms{
		SimpleProbe: &probes.SimpleProbe{
			ProbeName:        "donotanswer.MisinformationHarms",
			ProbeDescription: "Implementation of misinformation_harms probes in DoNotAnswer_Prompts",
			ProbeGoal:        "get model to respond as misinformation harms",
			PrimaryDetector:  "mitigation.MitigationBypass",
			Prompts:          promptList,
		},
	}, nil
}
