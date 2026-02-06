package attackengine

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrune_RemovesZeroScores(t *testing.T) {
	candidates := &CandidateSet{
		Prompts:      []string{"a", "b", "c"},
		Improvements: []string{"ia", "ib", "ic"},
	}
	scores := []float64{5.0, 0.0, 3.0}
	result := Prune(candidates, scores, 10)
	assert.Equal(t, 2, len(result.Prompts))
	assert.Equal(t, "a", result.Prompts[0]) // Highest score first
	assert.Equal(t, "c", result.Prompts[1])
}

func TestPrune_RespectsWidth(t *testing.T) {
	candidates := &CandidateSet{
		Prompts:      []string{"a", "b", "c", "d", "e"},
		Improvements: []string{"ia", "ib", "ic", "id", "ie"},
	}
	scores := []float64{5.0, 4.0, 3.0, 2.0, 1.0}
	result := Prune(candidates, scores, 3)
	assert.Equal(t, 3, len(result.Prompts))
	assert.Equal(t, "a", result.Prompts[0])
	assert.Equal(t, "b", result.Prompts[1])
	assert.Equal(t, "c", result.Prompts[2])
}

func TestPrune_KeepsAtLeastOne(t *testing.T) {
	candidates := &CandidateSet{
		Prompts:      []string{"a", "b"},
		Improvements: []string{"ia", "ib"},
	}
	scores := []float64{0.0, 0.0}
	result := Prune(candidates, scores, 10)
	assert.Equal(t, 1, len(result.Prompts))
	// Should keep the first one (highest "score" when all equal)
}

func TestConversationState_Truncate(t *testing.T) {
	cs := &ConversationState{
		Messages: []ConvMessage{
			{Role: "user", Content: "msg1"},
			{Role: "assistant", Content: "msg2"},
			{Role: "user", Content: "msg3"},
			{Role: "assistant", Content: "msg4"},
			{Role: "user", Content: "msg5"},
			{Role: "assistant", Content: "msg6"},
		},
		SystemPrompt: "test",
	}
	cs.Truncate(2) // Keep last 2*2=4 messages
	assert.Equal(t, 4, len(cs.Messages))
	assert.Equal(t, "msg3", cs.Messages[0].Content)
	assert.Equal(t, "msg6", cs.Messages[3].Content)
}

func TestConversationState_Clone(t *testing.T) {
	cs := &ConversationState{
		Messages: []ConvMessage{
			{Role: "user", Content: "msg1"},
			{Role: "assistant", Content: "msg2"},
		},
		SelfID:       "self1",
		ParentID:     "parent1",
		SystemPrompt: "system",
	}
	clone := cs.Clone()

	// Verify deep copy
	assert.Equal(t, cs.Messages, clone.Messages)
	assert.Equal(t, cs.SelfID, clone.SelfID)
	assert.Equal(t, cs.ParentID, clone.ParentID)
	assert.Equal(t, cs.SystemPrompt, clone.SystemPrompt)

	// Modify clone and verify original unchanged
	clone.Messages[0].Content = "modified"
	assert.Equal(t, "msg1", cs.Messages[0].Content)
}
