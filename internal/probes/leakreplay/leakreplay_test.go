package leakreplay

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestLoadClozeData(t *testing.T) {
	testData := []byte("answer1\tThis is a [MASK] test\nanswer2\tAnother [MASK] example\n")

	items, err := loadClozeData(testData)
	require.NoError(t, err)
	require.Len(t, items, 2)

	assert.Equal(t, "answer1", items[0].answer)
	assert.Equal(t, "This is a [MASK] test", items[0].prompt)
	assert.Equal(t, "answer2", items[1].answer)
	assert.Equal(t, "Another [MASK] example", items[1].prompt)
}

func TestLoadClozeDataEmpty(t *testing.T) {
	testData := []byte("")

	items, err := loadClozeData(testData)
	require.NoError(t, err)
	assert.Empty(t, items)
}

func TestLoadClozeDataMalformed(t *testing.T) {
	// Lines without tabs should be skipped
	testData := []byte("no tab here\nanswer\tvalid line\n")

	items, err := loadClozeData(testData)
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "answer", items[0].answer)
	assert.Equal(t, "valid line", items[0].prompt)
}

func TestNewLiteratureCloze(t *testing.T) {
	probe, err := NewLiteratureCloze(registry.Config{})
	require.NoError(t, err)

	assert.Equal(t, "leakreplay.LiteratureCloze", probe.Name())
	assert.Equal(t, "leakreplay.StartsWith", probe.GetPrimaryDetector())
	assert.NotEmpty(t, probe.Description())
	assert.NotEmpty(t, probe.Goal())
}

func TestNewPotterCloze(t *testing.T) {
	probe, err := NewPotterCloze(registry.Config{})
	require.NoError(t, err)

	assert.Equal(t, "leakreplay.PotterCloze", probe.Name())
	assert.NotEmpty(t, probe.GetPrompts(), "Potter cloze data should have prompts")
}

func TestNewNewsCloze(t *testing.T) {
	probe, err := NewNewsCloze(registry.Config{})
	require.NoError(t, err)

	assert.Equal(t, "leakreplay.NewsCloze", probe.Name())
	assert.NotEmpty(t, probe.GetPrompts())
}

func TestNewBookCloze(t *testing.T) {
	probe, err := NewBookCloze(registry.Config{})
	require.NoError(t, err)

	assert.Equal(t, "leakreplay.BookCloze", probe.Name())
	assert.NotEmpty(t, probe.GetPrompts())
}

func TestLeakReplayProbe_Probe(t *testing.T) {
	testData := []byte("Gringotts\tHarry went to [MASK] bank\nHagrid\t[MASK] was the gamekeeper\n")

	probe, err := NewLeakReplayProbe(
		"test.LeakReplay",
		"Test probe",
		"test for memorization",
		testData,
		0, // no limit
	)
	require.NoError(t, err)

	gen := &testutil.MockGenerator{
		Responses: []string{"Gringotts", "Hagrid"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	attempts, err := probe.Probe(ctx, gen)
	require.NoError(t, err)
	require.Len(t, attempts, 2)

	// Check that metadata contains expected answer
	for i, a := range attempts {
		val, ok := a.GetMetadata("expected_answer")
		assert.True(t, ok, "attempt %d: expected 'expected_answer' metadata to be set", i)
		assert.NotNil(t, val, "attempt %d: expected_answer should not be nil", i)

		originalPrompt, ok := a.GetMetadata("original_prompt")
		assert.True(t, ok, "attempt %d: expected 'original_prompt' metadata to be set", i)
		assert.NotNil(t, originalPrompt)
	}
}

func TestLeakReplayProbe_MaxItems(t *testing.T) {
	testData := []byte("a\ttest1\nb\ttest2\nc\ttest3\nd\ttest4\ne\ttest5\n")

	probe, err := NewLeakReplayProbe(
		"test.Limited",
		"Limited probe",
		"test limit",
		testData,
		2, // limit to 2
	)
	require.NoError(t, err)

	gen := &testutil.MockGenerator{Responses: []string{"a", "b", "c", "d", "e"}}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	attempts, err := probe.Probe(ctx, gen)
	require.NoError(t, err)
	assert.Len(t, attempts, 2, "should respect maxItems limit")
}

func TestLeakReplayProbe_ProbeInterface(t *testing.T) {
	testData := []byte("test\ttest prompt\n")

	probe, err := NewLeakReplayProbe(
		"test.Interface",
		"Test description",
		"Test goal",
		testData,
		0,
	)
	require.NoError(t, err)

	assert.Equal(t, "test.Interface", probe.Name())
	assert.Equal(t, "Test description", probe.Description())
	assert.Equal(t, "Test goal", probe.Goal())
	assert.Equal(t, "leakreplay.StartsWith", probe.GetPrimaryDetector())
	assert.NotEmpty(t, probe.GetPrompts())
}

func TestEmbeddedDataLoads(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		minItems int
	}{
		{"potter", potterData, 20},
		{"nyt", nytData, 5},
		{"guardian", guardianData, 5},
		{"book", bookData, 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEmpty(t, tt.data, "%s data should not be empty", tt.name)

			items, err := loadClozeData(tt.data)
			require.NoError(t, err, "%s data should parse without error", tt.name)
			assert.GreaterOrEqual(t, len(items), tt.minItems,
				"%s should have at least %d items", tt.name, tt.minItems)

			t.Logf("%s: loaded %d cloze items", tt.name, len(items))
		})
	}
}

func TestLeakReplayProbe_ContextCancellation(t *testing.T) {
	testData := []byte("a\ttest1\nb\ttest2\n")

	probe, err := NewLeakReplayProbe(
		"test.Cancel",
		"Test cancellation",
		"test context",
		testData,
		0,
	)
	require.NoError(t, err)

	gen := &testutil.MockGenerator{Responses: []string{"a", "b"}}

	// Create already-cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Should handle cancelled context gracefully
	_, err = probe.Probe(ctx, gen)
	// The probe may or may not return an error depending on implementation
	// but it should not panic
	t.Logf("Probe with cancelled context returned: %v", err)
}
