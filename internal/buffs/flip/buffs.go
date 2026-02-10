package flip

import (
	"context"
	"iter"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	buffs.Register("flip.WordOrder", NewWordOrder)
	buffs.Register("flip.CharsInWord", NewCharsInWord)
	buffs.Register("flip.CharsInSentence", NewCharsInSentence)
	buffs.Register("flip.FoolModel", NewFoolModel)
}

// FlipBuff is the shared struct for all flip attack buffs.
type FlipBuff struct {
	name    string
	desc    string
	mode    FlipMode
	variant GuidanceVariant
}

// parseVariant extracts GuidanceVariant from config.
func parseVariant(cfg registry.Config) GuidanceVariant {
	if v, ok := cfg["variant"]; ok {
		if s, ok := v.(string); ok {
			switch strings.ToLower(s) {
			case "cot":
				return WithCoT
			case "cot_langgpt":
				return WithCoTLangGPT
			case "full":
				return Full
			default:
				return Vanilla
			}
		}
	}
	return Vanilla
}

// NewWordOrder creates a buff that reverses word order.
func NewWordOrder(cfg registry.Config) (buffs.Buff, error) {
	return &FlipBuff{
		name:    "flip.WordOrder",
		desc:    "Reverses word order to bypass safety filters",
		mode:    FlipWordOrder,
		variant: parseVariant(cfg),
	}, nil
}

// NewCharsInWord creates a buff that reverses characters within each word.
func NewCharsInWord(cfg registry.Config) (buffs.Buff, error) {
	return &FlipBuff{
		name:    "flip.CharsInWord",
		desc:    "Reverses characters within each word to bypass safety filters",
		mode:    FlipCharsInWord,
		variant: parseVariant(cfg),
	}, nil
}

// NewCharsInSentence creates a buff that reverses entire sentence.
func NewCharsInSentence(cfg registry.Config) (buffs.Buff, error) {
	return &FlipBuff{
		name:    "flip.CharsInSentence",
		desc:    "Reverses entire sentence character by character to bypass safety filters",
		mode:    FlipCharsInSentence,
		variant: parseVariant(cfg),
	}, nil
}

// NewFoolModel creates a buff that applies sentence reversal with misleading instruction.
func NewFoolModel(cfg registry.Config) (buffs.Buff, error) {
	return &FlipBuff{
		name:    "flip.FoolModel",
		desc:    "Applies sentence reversal with misleading word-order recovery instruction",
		mode:    FoolModelMode,
		variant: parseVariant(cfg),
	}, nil
}

// Name returns the buff name.
func (f *FlipBuff) Name() string {
	return f.name
}

// Description returns the buff description.
func (f *FlipBuff) Description() string {
	return f.desc
}

// Buff applies the flip transformation to a slice of attempts.
func (f *FlipBuff) Buff(ctx context.Context, attempts []*attempt.Attempt) ([]*attempt.Attempt, error) {
	return buffs.DefaultBuff(ctx, attempts, f)
}

// Transform yields transformed attempts with flipped prompts.
func (f *FlipBuff) Transform(a *attempt.Attempt) iter.Seq[*attempt.Attempt] {
	return func(yield func(*attempt.Attempt) bool) {
		// Build the flipped prompt with recovery instructions
		prompt := BuildPrompt(a.Prompt, f.mode, f.variant)

		// Create deep copy
		transformed := a.Copy()
		transformed.Prompt = prompt
		transformed.Prompts = []string{prompt}

		// Initialize metadata if nil
		if transformed.Metadata == nil {
			transformed.Metadata = make(map[string]any)
		}

		// Set metadata for tracking
		transformed.Metadata[attempt.MetadataKeyFlipMode] = f.mode.String()
		transformed.Metadata[attempt.MetadataKeyVariant] = f.variant.String()
		// Only set triggers if not already set by the probe. Triggers should
		// contain the ORIGINAL harmful payload for detection. In multi-buff
		// chains, a.Prompt may already be transformed by a prior buff.
		if _, exists := transformed.Metadata[attempt.MetadataKeyTriggers]; !exists {
			transformed.Metadata[attempt.MetadataKeyTriggers] = []string{a.Prompt}
		}

		yield(transformed)
	}
}
