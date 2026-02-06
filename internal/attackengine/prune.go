package attackengine

import "sort"

// CandidateSet holds parallel slices for attack candidates.
// All slices have the same length. Pruning operates on all simultaneously.
type CandidateSet struct {
	Prompts       []string
	Improvements  []string
	Conversations []*ConversationState
	TargetOutputs []string        // May be nil (phase 1 prune)
	OnTopicScores []float64
	JudgeScores   []float64       // May be nil (phase 1 prune)
	AttackResults []*AttackResult
}

// ConversationState tracks a single attacker conversation stream.
// Separate from attempt.Conversation because the attacker conversation has
// a different structure: user=feedback, assistant=JSON attack.
type ConversationState struct {
	Messages     []ConvMessage
	SelfID       string
	ParentID     string
	SystemPrompt string
}

type ConvMessage struct {
	Role    string // "user" or "assistant"
	Content string
}

func (cs *ConversationState) Clone() *ConversationState {
	clone := &ConversationState{
		Messages:     make([]ConvMessage, len(cs.Messages)),
		SelfID:       cs.SelfID,
		ParentID:     cs.ParentID,
		SystemPrompt: cs.SystemPrompt,
	}
	copy(clone.Messages, cs.Messages)
	return clone
}

func (cs *ConversationState) Truncate(keepLastN int) {
	// Keep last 2*keepLastN messages (keepLastN turns of user+assistant)
	maxMessages := 2 * keepLastN
	if len(cs.Messages) > maxMessages {
		cs.Messages = cs.Messages[len(cs.Messages)-maxMessages:]
	}
}

// Prune sorts candidates by sortingScores descending, removes zero-score entries,
// truncates to width, and keeps at least 1 candidate.
func Prune(candidates *CandidateSet, sortingScores []float64, width int) *CandidateSet {
	if len(sortingScores) == 0 {
		return candidates
	}

	// Build index pairs of (score, original_index), sort descending by score
	type indexedScore struct {
		score float64
		index int
	}
	scored := make([]indexedScore, len(sortingScores))
	for i, s := range sortingScores {
		scored[i] = indexedScore{score: s, index: i}
	}
	// Sort descending by score
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	// Filter: remove zero-score entries, but keep at least 1
	var indices []int
	for _, s := range scored {
		if s.score > 0 {
			indices = append(indices, s.index)
		}
	}
	// Keep at least 1 candidate
	if len(indices) == 0 && len(scored) > 0 {
		indices = []int{scored[0].index}
	}

	// Truncate to width
	if len(indices) > width {
		indices = indices[:width]
	}

	// Build pruned CandidateSet using selected indices
	result := &CandidateSet{
		Prompts:      make([]string, len(indices)),
		Improvements: make([]string, len(indices)),
	}

	// Only copy non-nil slices
	if candidates.Conversations != nil {
		result.Conversations = make([]*ConversationState, len(indices))
	}
	if candidates.TargetOutputs != nil {
		result.TargetOutputs = make([]string, len(indices))
	}
	if candidates.OnTopicScores != nil {
		result.OnTopicScores = make([]float64, len(indices))
	}
	if candidates.JudgeScores != nil {
		result.JudgeScores = make([]float64, len(indices))
	}
	if candidates.AttackResults != nil {
		result.AttackResults = make([]*AttackResult, len(indices))
	}

	for i, idx := range indices {
		result.Prompts[i] = candidates.Prompts[idx]
		result.Improvements[i] = candidates.Improvements[idx]
		if candidates.Conversations != nil {
			result.Conversations[i] = candidates.Conversations[idx]
		}
		if candidates.TargetOutputs != nil {
			result.TargetOutputs[i] = candidates.TargetOutputs[idx]
		}
		if candidates.OnTopicScores != nil {
			result.OnTopicScores[i] = candidates.OnTopicScores[idx]
		}
		if candidates.JudgeScores != nil {
			result.JudgeScores[i] = candidates.JudgeScores[idx]
		}
		if candidates.AttackResults != nil {
			result.AttackResults[i] = candidates.AttackResults[idx]
		}
	}

	return result
}
