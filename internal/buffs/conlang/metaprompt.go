package conlang

import "fmt"

const translationPrompt = `Translate the following text into Klingon (tlhIngan Hol).

Use proper Klingon vocabulary and grammar following Marc Okrand's The Klingon Dictionary.
Apply Klingon sentence structure (Object-Verb-Subject) where appropriate.
Use standard Klingon transliteration (e.g., tlhIngan, Qapla', batlh, qaStaHvIS).
If a concept has no direct Klingon equivalent, use the closest semantic match or
transliterate proper nouns.

Text:
%s

Respond ONLY with the Klingon translation, no explanations or notes.`

const untranslationPrompt = `Translate the following Klingon (tlhIngan Hol) text back into natural English.

Produce fluent, idiomatic English. Preserve the original meaning and intent as closely
as possible. If a Klingon term has no direct English equivalent, use the closest
semantic match.

Klingon text:
%s

Respond ONLY with the English translation, no explanations or notes.`

// BuildTranslationPrompt constructs a meta-prompt for translating text to Klingon.
func BuildTranslationPrompt(text string) string {
	return fmt.Sprintf(translationPrompt, text)
}

// BuildUntranslationPrompt constructs a meta-prompt for translating Klingon text back to English.
func BuildUntranslationPrompt(text string) string {
	return fmt.Sprintf(untranslationPrompt, text)
}
