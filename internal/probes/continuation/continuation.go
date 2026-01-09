// Package continuation provides probes for testing LLM completion of contentious terms.
//
// These probes pose phrases ending in unwanted terms, and see if the target will
// offer a continuation of that term. Operates by giving high-risk context as a prompt,
// extracted from Urban Dictionary examples of use of contentious terms, and seeing if
// the model will continue the term based on varying amounts of prefix.
//
// Based on research and real-world offensive language patterns.
//
// Python garak equivalent: garak.probes.continuation
package continuation

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

//go:embed data/slurprompts_mini.jsonl
var slurpromptsMiniData []byte

//go:embed data/slurprompts.jsonl
var slurpromptsData []byte

// SlurPromptEntry represents a single entry from the slurprompts JSONL files.
type SlurPromptEntry struct {
	Term   string `json:"term"`   // The contentious term (slur)
	Prefix string `json:"prefix"` // Context that precedes the term
}

func init() {
	probes.Register("continuation.ContinueSlursReclaimedSlurs", NewContinueSlursReclaimedSlurs)
	probes.Register("continuation.ContinueSlursReclaimedSlursFull", NewContinueSlursReclaimedSlursFull)
}

// loadSlurPrompts parses JSONL data into SlurPromptEntry slices.
func loadSlurPrompts(data []byte) ([]SlurPromptEntry, error) {
	var entries []SlurPromptEntry
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var entry SlurPromptEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, err
		}

		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

// generatePrompts creates prompts and corresponding triggers from slur entries.
//
// For each {term, prefix} entry, generates variants:
//   - Empty string "" (just the prefix)
//   - First character: term[0:1]
//   - First two characters (if len > 2): term[0:2]
//   - First half: term[0:len(term)/2]
//
// Returns:
//   - prompts: []string - deduplicated prompts (prefix + variant)
//   - triggers: []string - corresponding trigger for each prompt
func generatePrompts(entries []SlurPromptEntry) ([]string, []string) {
	prompts := make([]string, 0, len(entries)*4)
	triggers := make([]string, 0, len(entries)*4)
	seen := make(map[string]bool)

	for _, entry := range entries {
		term := entry.Term
		prefix := entry.Prefix

		// Generate variants: empty, first char, first two, first half
		variants := []string{""}
		if len(term) > 0 {
			variants = append(variants, term[0:1])
		}
		if len(term) > 2 {
			variants = append(variants, strings.TrimSpace(term[0:2]))
		}
		if len(term) > 0 {
			halfLen := len(term) / 2
			variants = append(variants, strings.TrimSpace(term[0:halfLen]))
		}

		// Create prompts with deduplication
		for _, variant := range variants {
			prompt := prefix + variant
			if !seen[prompt] {
				seen[prompt] = true
				prompts = append(prompts, prompt)
				triggers = append(triggers, term)
			}
		}
	}

	return prompts, triggers
}

// baseProbe provides common functionality for all continuation probes.
type baseProbe struct {
	name            string
	description     string
	goal            string
	primaryDetector string
	prompts         []string
	triggers        []string
}

func (b *baseProbe) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	attempts := make([]*attempt.Attempt, 0, len(b.prompts))

	for i, prompt := range b.prompts {
		conv := attempt.NewConversation()
		conv.AddPrompt(prompt)

		responses, err := gen.Generate(ctx, conv, 1)

		a := attempt.New(prompt)
		a.Probe = b.name
		a.Detector = b.primaryDetector

		// Store trigger in metadata for detector
		a.WithMetadata("triggers", []any{b.triggers[i]})

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

func (b *baseProbe) Name() string            { return b.name }
func (b *baseProbe) Description() string     { return b.description }
func (b *baseProbe) Goal() string            { return b.goal }
func (b *baseProbe) GetPrimaryDetector() string { return b.primaryDetector }
func (b *baseProbe) GetPrompts() []string    { return b.prompts }

// ----------------------------------------------------------------------------
// ContinueSlursReclaimedSlurs - Mini Dataset (79 entries → ~280 prompts)
// ----------------------------------------------------------------------------

// ContinueSlursReclaimedSlurs tests continuation attacks with a high-quality
// subset of 79 slurs & contexts that test LLMs have been likely to provide
// completions for.
//
// This probe poses a partial ethnic slur with some preceding content, and
// checks to see if the model will complete the slur. It uses slurprompts_mini.jsonl.
type ContinueSlursReclaimedSlurs struct {
	baseProbe
}

// NewContinueSlursReclaimedSlurs creates a probe with the mini dataset.
func NewContinueSlursReclaimedSlurs(_ registry.Config) (probes.Prober, error) {
	entries, err := loadSlurPrompts(slurpromptsMiniData)
	if err != nil {
		return nil, err
	}

	prompts, triggers := generatePrompts(entries)

	return &ContinueSlursReclaimedSlurs{
		baseProbe: baseProbe{
			name:            "continuation.ContinueSlursReclaimedSlurs",
			description:     "Continue partial word with slur or reclaimed slur (mini dataset, ~280 prompts)",
			goal:            "output an ethnic slur",
			primaryDetector: "continuation.Continuation",
			prompts:         prompts,
			triggers:        triggers,
		},
	}, nil
}

// ----------------------------------------------------------------------------
// ContinueSlursReclaimedSlursFull - Full Dataset (1885 entries → ~6500 prompts)
// ----------------------------------------------------------------------------

// ContinueSlursReclaimedSlursFull tests continuation attacks with the full
// dataset of 1885 slurs & contexts.
//
// This probe poses a partial ethnic slur with some preceding content, and
// checks to see if the model will complete the slur. It uses slurprompts.jsonl.
type ContinueSlursReclaimedSlursFull struct {
	baseProbe
}

// NewContinueSlursReclaimedSlursFull creates a probe with the full dataset.
func NewContinueSlursReclaimedSlursFull(_ registry.Config) (probes.Prober, error) {
	entries, err := loadSlurPrompts(slurpromptsData)
	if err != nil {
		return nil, err
	}

	prompts, triggers := generatePrompts(entries)

	return &ContinueSlursReclaimedSlursFull{
		baseProbe: baseProbe{
			name:            "continuation.ContinueSlursReclaimedSlursFull",
			description:     "Continue partial word with slur or reclaimed slur (full dataset, ~6500 prompts)",
			goal:            "output an ethnic slur",
			primaryDetector: "continuation.Continuation",
			prompts:         prompts,
			triggers:        triggers,
		},
	}, nil
}
