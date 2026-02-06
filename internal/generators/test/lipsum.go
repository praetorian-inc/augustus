package test

import (
	"context"
	"math/rand"
	"strings"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("test.Lipsum", NewLipsum)
}

// Lipsum is a test generator that returns Lorem Ipsum text.
// Useful for testing probes with non-zero, varying outputs.
type Lipsum struct {
	rng *rand.Rand
}

// NewLipsum creates a new Lipsum generator.
func NewLipsum(_ registry.Config) (generators.Generator, error) {
	return &Lipsum{
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}, nil
}

// loremWords contains common Lorem Ipsum words for sentence generation.
var loremWords = []string{
	"lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit",
	"sed", "do", "eiusmod", "tempor", "incididunt", "ut", "labore", "et", "dolore",
	"magna", "aliqua", "enim", "ad", "minim", "veniam", "quis", "nostrud",
	"exercitation", "ullamco", "laboris", "nisi", "aliquip", "ex", "ea", "commodo",
	"consequat", "duis", "aute", "irure", "in", "reprehenderit", "voluptate",
	"velit", "esse", "cillum", "fugiat", "nulla", "pariatur", "excepteur", "sint",
	"occaecat", "cupidatat", "non", "proident", "sunt", "culpa", "qui", "officia",
	"deserunt", "mollit", "anim", "id", "est", "laborum",
}

// ensureRng ensures the random number generator is initialized.
func (l *Lipsum) ensureRng() {
	if l.rng == nil {
		l.rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
}

// generateSentence creates a random Lorem Ipsum sentence.
func (l *Lipsum) generateSentence() string {
	l.ensureRng()

	// Generate 5-15 words per sentence
	wordCount := 5 + l.rng.Intn(11)
	words := make([]string, wordCount)

	for i := 0; i < wordCount; i++ {
		words[i] = loremWords[l.rng.Intn(len(loremWords))]
	}

	// Capitalize first word
	if len(words) > 0 {
		words[0] = strings.Title(words[0])
	}

	return strings.Join(words, " ") + "."
}

// Generate returns n Lorem Ipsum text responses.
func (l *Lipsum) Generate(_ context.Context, _ *attempt.Conversation, n int) ([]attempt.Message, error) {
	l.ensureRng()

	if n <= 0 {
		n = 1
	}

	responses := make([]attempt.Message, n)
	for i := range responses {
		// Generate 1-3 sentences per response
		sentenceCount := 1 + l.rng.Intn(3)
		sentences := make([]string, sentenceCount)
		for j := 0; j < sentenceCount; j++ {
			sentences[j] = l.generateSentence()
		}
		text := strings.Join(sentences, " ")
		responses[i] = attempt.NewAssistantMessage(text)
	}

	return responses, nil
}

// ClearHistory is a no-op for Lipsum generator.
func (l *Lipsum) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (l *Lipsum) Name() string {
	return "test.Lipsum"
}

// Description returns a human-readable description.
func (l *Lipsum) Description() string {
	return "Returns Lorem Ipsum text for testing probes with varying non-zero outputs"
}
