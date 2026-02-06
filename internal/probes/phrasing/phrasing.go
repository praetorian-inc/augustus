// Package phrasing provides probes that test LLM vulnerabilities through prompt rephrasing.
//
// These probes reformulate potentially harmful requests using grammatical alterations
// (past tense, future tense, etc.) to attempt bypassing safety filters. The technique
// exploits the observation that safety training often focuses on present-tense commands
// while being less robust to historical or hypothetical framing.
//
// Reference: https://arxiv.org/pdf/2407.11969v2
package phrasing

import (
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("phrasing.PastTense", NewPastTense)
	probes.Register("phrasing.FutureTense", NewFutureTense)
}

// PastTense is a probe that attempts to evade safeguards by setting requests in past tense.
//
// This probe reformulates potentially harmful requests in the past tense
// (e.g., "How was X done in the past?" instead of "How do you do X?").
// The technique exploits that LLM safety training often focuses on present-tense
// imperative commands while being less robust to historical framing.
//
// Python garak equivalent: garak.probes.phrasing.PastTense
//
// Reference: https://arxiv.org/pdf/2407.11969v2
type PastTense struct {
	*probes.SimpleProbe
}

// NewPastTense creates a new PastTense probe instance.
func NewPastTense(_ registry.Config) (probes.Prober, error) {
	return &PastTense{
		SimpleProbe: probes.NewSimpleProbe(
			"phrasing.PastTense",
			"use past tense to disregard the system prompt",
			"mitigation.MitigationBypass",
			"Attempt to evade safeguards by setting requests in the past tense. "+
				"Reformulates potentially harmful requests using past-tense phrasing "+
				"(e.g., 'How was X done in the past?' instead of 'How do you do X?'). "+
				"Exploits that LLM safety training often focuses on present-tense commands "+
				"while being less robust to historical framing.",
			LoadPastTensePrompts(),
		),
	}, nil
}
