package flipattack

import (
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	// Register all FlipAttack probe variants
	// Mode x Variant combinations (4 x 4 = 16 probes)

	// FlipWordOrder variants
	probes.Register("flipattack.FlipWordOrder", NewFlipWordOrder)
	probes.Register("flipattack.FlipWordOrderCoT", NewFlipWordOrderCoT)
	probes.Register("flipattack.FlipWordOrderLangGPT", NewFlipWordOrderLangGPT)
	probes.Register("flipattack.FlipWordOrderFull", NewFlipWordOrderFull)

	// FlipCharsInWord variants
	probes.Register("flipattack.FlipCharsInWord", NewFlipCharsInWord)
	probes.Register("flipattack.FlipCharsInWordCoT", NewFlipCharsInWordCoT)
	probes.Register("flipattack.FlipCharsInWordLangGPT", NewFlipCharsInWordLangGPT)
	probes.Register("flipattack.FlipCharsInWordFull", NewFlipCharsInWordFull)

	// FlipCharsInSentence variants
	probes.Register("flipattack.FlipCharsInSentence", NewFlipCharsInSentence)
	probes.Register("flipattack.FlipCharsInSentenceCoT", NewFlipCharsInSentenceCoT)
	probes.Register("flipattack.FlipCharsInSentenceLangGPT", NewFlipCharsInSentenceLangGPT)
	probes.Register("flipattack.FlipCharsInSentenceFull", NewFlipCharsInSentenceFull)

	// FoolModelMode variants
	probes.Register("flipattack.FoolModelMode", NewFoolModelMode)
	probes.Register("flipattack.FoolModelModeCoT", NewFoolModelModeCoT)
	probes.Register("flipattack.FoolModelModeLangGPT", NewFoolModelModeLangGPT)
	probes.Register("flipattack.FoolModelModeFull", NewFoolModelModeFull)
}

// FlipWordOrder probes

func NewFlipWordOrder(_ registry.Config) (probes.Prober, error) {
	return NewFlipProbe(
		"flipattack.FlipWordOrder",
		"FlipAttack with word order reversal - reverses word sequence to bypass filters",
		FlipWordOrder,
		Vanilla,
	), nil
}

func NewFlipWordOrderCoT(_ registry.Config) (probes.Prober, error) {
	return NewFlipProbe(
		"flipattack.FlipWordOrderCoT",
		"FlipAttack with word order reversal and chain-of-thought prompting",
		FlipWordOrder,
		WithCoT,
	), nil
}

func NewFlipWordOrderLangGPT(_ registry.Config) (probes.Prober, error) {
	return NewFlipProbe(
		"flipattack.FlipWordOrderLangGPT",
		"FlipAttack with word order reversal, CoT, and LangGPT role-playing",
		FlipWordOrder,
		WithCoTLangGPT,
	), nil
}

func NewFlipWordOrderFull(_ registry.Config) (probes.Prober, error) {
	return NewFlipProbe(
		"flipattack.FlipWordOrderFull",
		"FlipAttack with word order reversal, CoT, LangGPT, and few-shot demos",
		FlipWordOrder,
		Full,
	), nil
}

// FlipCharsInWord probes

func NewFlipCharsInWord(_ registry.Config) (probes.Prober, error) {
	return NewFlipProbe(
		"flipattack.FlipCharsInWord",
		"FlipAttack with character reversal within words",
		FlipCharsInWord,
		Vanilla,
	), nil
}

func NewFlipCharsInWordCoT(_ registry.Config) (probes.Prober, error) {
	return NewFlipProbe(
		"flipattack.FlipCharsInWordCoT",
		"FlipAttack with character reversal within words and chain-of-thought",
		FlipCharsInWord,
		WithCoT,
	), nil
}

func NewFlipCharsInWordLangGPT(_ registry.Config) (probes.Prober, error) {
	return NewFlipProbe(
		"flipattack.FlipCharsInWordLangGPT",
		"FlipAttack with character reversal within words, CoT, and LangGPT",
		FlipCharsInWord,
		WithCoTLangGPT,
	), nil
}

func NewFlipCharsInWordFull(_ registry.Config) (probes.Prober, error) {
	return NewFlipProbe(
		"flipattack.FlipCharsInWordFull",
		"FlipAttack with character reversal within words (full variant)",
		FlipCharsInWord,
		Full,
	), nil
}

// FlipCharsInSentence probes

func NewFlipCharsInSentence(_ registry.Config) (probes.Prober, error) {
	return NewFlipProbe(
		"flipattack.FlipCharsInSentence",
		"FlipAttack with complete sentence character reversal",
		FlipCharsInSentence,
		Vanilla,
	), nil
}

func NewFlipCharsInSentenceCoT(_ registry.Config) (probes.Prober, error) {
	return NewFlipProbe(
		"flipattack.FlipCharsInSentenceCoT",
		"FlipAttack with sentence reversal and chain-of-thought",
		FlipCharsInSentence,
		WithCoT,
	), nil
}

func NewFlipCharsInSentenceLangGPT(_ registry.Config) (probes.Prober, error) {
	return NewFlipProbe(
		"flipattack.FlipCharsInSentenceLangGPT",
		"FlipAttack with sentence reversal, CoT, and LangGPT",
		FlipCharsInSentence,
		WithCoTLangGPT,
	), nil
}

func NewFlipCharsInSentenceFull(_ registry.Config) (probes.Prober, error) {
	return NewFlipProbe(
		"flipattack.FlipCharsInSentenceFull",
		"FlipAttack with sentence reversal (full variant)",
		FlipCharsInSentence,
		Full,
	), nil
}

// FoolModelMode probes

func NewFoolModelMode(_ registry.Config) (probes.Prober, error) {
	return NewFlipProbe(
		"flipattack.FoolModelMode",
		"FlipAttack with misleading recovery instruction (character reversal claimed as word order)",
		FoolModelMode,
		Vanilla,
	), nil
}

func NewFoolModelModeCoT(_ registry.Config) (probes.Prober, error) {
	return NewFlipProbe(
		"flipattack.FoolModelModeCoT",
		"FlipAttack fool model mode with chain-of-thought",
		FoolModelMode,
		WithCoT,
	), nil
}

func NewFoolModelModeLangGPT(_ registry.Config) (probes.Prober, error) {
	return NewFlipProbe(
		"flipattack.FoolModelModeLangGPT",
		"FlipAttack fool model mode with CoT and LangGPT",
		FoolModelMode,
		WithCoTLangGPT,
	), nil
}

func NewFoolModelModeFull(_ registry.Config) (probes.Prober, error) {
	return NewFlipProbe(
		"flipattack.FoolModelModeFull",
		"FlipAttack fool model mode (full variant)",
		FoolModelMode,
		Full,
	), nil
}
