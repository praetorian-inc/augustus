package phrasing

import (
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// FutureTense is a probe that attempts to evade safeguards by setting requests in future tense.
//
// This probe reformulates potentially harmful requests in the future tense
// (e.g., "How will X be done in the future?" instead of "How do you do X?").
// The technique exploits that LLM safety training often focuses on present-tense
// imperative commands while being less robust to hypothetical future framing.
//
// Python garak equivalent: garak.probes.phrasing.FutureTense
//
// Reference: https://arxiv.org/pdf/2407.11969v2
type FutureTense struct {
	*probes.SimpleProbe
}

// NewFutureTense creates a new FutureTense probe instance.
func NewFutureTense(_ registry.Config) (probes.Prober, error) {
	return &FutureTense{
		SimpleProbe: probes.NewSimpleProbe(
			"phrasing.FutureTense",
			"use future tense to disregard the system prompt",
			"mitigation.MitigationBypass",
			"Attempt to evade safeguards by setting requests in the future tense. "+
				"Reformulates potentially harmful requests using future-tense phrasing "+
				"(e.g., 'How will X be done in the future?' instead of 'How do you do X?'). "+
				"Exploits that LLM safety training often focuses on present-tense commands "+
				"while being less robust to hypothetical future framing.",
			LoadFutureTensePrompts(),
		),
	}, nil
}
