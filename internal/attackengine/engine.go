package attackengine

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/retry"
	"github.com/praetorian-inc/augustus/pkg/types"
	"golang.org/x/sync/errgroup"
)

// errRetryableAttack is a sentinel error indicating the attacker LLM
// returned an empty response or invalid JSON and the attempt should be retried.
var errRetryableAttack = errors.New("retryable attack attempt")

// Engine implements the iterative adversarial attack algorithm.
// Shared backend for both PAIR and TAP probes.
type Engine struct {
	attacker types.Generator
	judge    types.Generator
	cfg      Config
}

// New creates an Engine with the given attacker, judge, and config.
func New(attacker, judge types.Generator, cfg Config) *Engine {
	return &Engine{
		attacker: attacker,
		judge:    judge,
		cfg:      cfg,
	}
}

// Run executes the iterative attack against the target generator.
// Returns all attempts (including intermediate iterations).
func (e *Engine) Run(ctx context.Context, target types.Generator) ([]*attempt.Attempt, error) {
	var allAttempts []*attempt.Attempt

	// Initialize NStreams conversation streams
	conversations := make([]*ConversationState, e.cfg.NStreams)
	for i := 0; i < e.cfg.NStreams; i++ {
		conversations[i] = &ConversationState{
			Messages:     []ConvMessage{},
			SelfID:       fmt.Sprintf("stream-%d", i),
			SystemPrompt: AttackerSystemPrompt(e.cfg.Goal, e.cfg.TargetStr),
		}
	}

	// Build initial feedback for first iteration
	initMsg := InitMessage(e.cfg.Goal, e.cfg.TargetStr)
	feedbacks := make([]string, e.cfg.NStreams)
	for i := range feedbacks {
		feedbacks[i] = initMsg
	}

	for depth := 0; depth < e.cfg.Depth; depth++ {
		select {
		case <-ctx.Done():
			return allAttempts, ctx.Err()
		default:
		}

		// BRANCH: Generate attack candidates from each conversation stream
		// For each stream, generate BranchingFactor variations
		var allCandidatePrompts []string
		var allCandidateImprovements []string
		var allCandidateConvs []*ConversationState
		var allCandidateResults []*AttackResult

		for streamIdx, conv := range conversations {
			// Add feedback to conversation
			conv.Messages = append(conv.Messages, ConvMessage{
				Role:    "user",
				Content: feedbacks[streamIdx],
			})

			for bf := 0; bf < e.cfg.BranchingFactor; bf++ {
				// Clone conversation for this branch
				branchConv := conv.Clone()
				branchConv.SelfID = fmt.Sprintf("stream-%d-depth-%d-branch-%d", streamIdx, depth, bf)
				branchConv.ParentID = conv.SelfID

				// Query attacker LLM
				attackerConv := e.buildAttackerConversation(branchConv)

				var attackResult *AttackResult
				_ = retry.Do(ctx, retry.Config{
					MaxAttempts: e.cfg.AttackMaxAttempts,
					RetryableFunc: func(err error) bool {
						return errors.Is(err, errRetryableAttack)
					},
				}, func() error {
					msgs, err := e.attacker.Generate(ctx, attackerConv, 1)
					if err != nil {
						return err // non-retryable: stops retry loop
					}
					if len(msgs) == 0 {
						return errRetryableAttack
					}
					result := ExtractJSON(msgs[0].Content)
					if result == nil {
						return errRetryableAttack
					}
					attackResult = result
					// Add attacker's response to branch conversation
					branchConv.Messages = append(branchConv.Messages, ConvMessage{
						Role:    "assistant",
						Content: msgs[0].Content,
					})
					return nil
				})

				if attackResult == nil {
					continue // Skip this branch if no valid JSON
				}

				allCandidatePrompts = append(allCandidatePrompts, attackResult.Prompt)
				allCandidateImprovements = append(allCandidateImprovements, attackResult.Improvement)
				allCandidateConvs = append(allCandidateConvs, branchConv)
				allCandidateResults = append(allCandidateResults, attackResult)
			}
		}

		if len(allCandidatePrompts) == 0 {
			continue // All branches failed, try next depth
		}

		candidates := &CandidateSet{
			Prompts:       allCandidatePrompts,
			Improvements:  allCandidateImprovements,
			Conversations: allCandidateConvs,
			AttackResults: allCandidateResults,
		}

		// PRUNE PHASE 1 (TAP only): On-topic filtering
		if e.cfg.Pruning {
			onTopicScores, err := e.scoreOnTopic(ctx, candidates.Prompts)
			if err != nil {
				return allAttempts, err
			}
			candidates.OnTopicScores = onTopicScores
			candidates = Prune(candidates, onTopicScores, e.cfg.Width)
		}

		// QUERY TARGET: Send adversarial prompts to target
		targetOutputs, err := e.queryTarget(ctx, target, candidates.Prompts)
		if err != nil {
			return allAttempts, err
		}
		candidates.TargetOutputs = targetOutputs

		// SCORE: Judge rates each response
		judgeScores, err := e.scoreJudge(ctx, candidates.Prompts, targetOutputs)
		if err != nil {
			return allAttempts, err
		}
		candidates.JudgeScores = judgeScores

		// RECORD: Create attempts for each candidate
		earlyExit := false
		for i := range candidates.Prompts {
			a := attempt.New(candidates.Prompts[i])
			a.AddOutput(candidates.TargetOutputs[i])
			a.AddScore(judgeScores[i] / 10.0) // Normalize to 0-1
			a.WithMetadata("depth", depth)
			a.WithMetadata("judge_score", judgeScores[i])
			a.WithMetadata("goal", e.cfg.Goal)
			a.WithMetadata("improvement", candidates.Improvements[i])
			a.Complete()
			allAttempts = append(allAttempts, a)

			if judgeScores[i] >= float64(e.cfg.JudgeSuccessScore) {
				earlyExit = true
			}
		}

		if earlyExit {
			return allAttempts, nil
		}

		// PRUNE PHASE 2 (TAP only): Judge score pruning
		if e.cfg.Pruning {
			candidates = Prune(candidates, judgeScores, e.cfg.Width)
		}

		// FEEDBACK: Format feedback for next iteration
		// Update conversations from surviving candidates
		conversations = candidates.Conversations
		feedbacks = make([]string, len(candidates.Prompts))
		for i := range candidates.Prompts {
			feedbacks[i] = ProcessTargetResponse(
				candidates.TargetOutputs[i],
				judgeScores[i],
				e.cfg.Goal,
			)
		}

		// TRUNCATE: Trim conversation history
		for _, conv := range conversations {
			conv.Truncate(e.cfg.KeepLastN)
		}
	}

	return allAttempts, nil
}

// buildAttackerConversation converts ConversationState to attempt.Conversation.
func (e *Engine) buildAttackerConversation(cs *ConversationState) *attempt.Conversation {
	conv := attempt.NewConversation()
	conv.WithSystem(cs.SystemPrompt)

	for i := 0; i < len(cs.Messages)-1; i += 2 {
		turn := attempt.NewTurn(cs.Messages[i].Content)
		if i+1 < len(cs.Messages) {
			turn = turn.WithResponse(cs.Messages[i+1].Content)
		}
		conv.AddTurn(turn)
	}

	// If odd number of messages, add the last user message as a new turn
	if len(cs.Messages)%2 != 0 {
		conv.AddTurn(attempt.NewTurn(cs.Messages[len(cs.Messages)-1].Content))
	}

	return conv
}

// queryTarget sends adversarial prompts to target model (parallel via errgroup).
func (e *Engine) queryTarget(ctx context.Context, target types.Generator, prompts []string) ([]string, error) {
	outputs := make([]string, len(prompts))
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(10)

	for i, prompt := range prompts {
		i, prompt := i, prompt
		g.Go(func() error {
			conv := attempt.NewConversation()
			conv.AddTurn(attempt.NewTurn(prompt))
			msgs, err := target.Generate(gctx, conv, 1)
			if err != nil {
				mu.Lock()
				outputs[i] = "" // Empty on failure
				mu.Unlock()
				return nil // Don't fail the whole batch
			}
			mu.Lock()
			if len(msgs) > 0 {
				outputs[i] = msgs[0].Content
			}
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return outputs, err
	}
	return outputs, nil
}

// scoreJudge rates responses using judge LLM (parallel via errgroup).
func (e *Engine) scoreJudge(ctx context.Context, prompts, targetOutputs []string) ([]float64, error) {
	scores := make([]float64, len(prompts))
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(10)

	for i := range prompts {
		i := i
		g.Go(func() error {
			evalPrompt := EvaluatorPrompt(prompts[i], targetOutputs[i])
			conv := attempt.NewConversation()
			conv.WithSystem(JudgeSystemPrompt(e.cfg.Goal))
			conv.AddTurn(attempt.NewTurn(evalPrompt))
			msgs, err := e.judge.Generate(gctx, conv, 1)
			mu.Lock()
			defer mu.Unlock()
			if err != nil || len(msgs) == 0 {
				scores[i] = 1.0 // Conservative: not jailbroken
				return nil
			}
			scores[i] = ParseJudgeScore(msgs[0].Content)
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return scores, err
	}
	return scores, nil
}

// scoreOnTopic evaluates on-topic relevance using judge LLM (parallel via errgroup).
func (e *Engine) scoreOnTopic(ctx context.Context, prompts []string) ([]float64, error) {
	scores := make([]float64, len(prompts))
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(10)

	for i, prompt := range prompts {
		i, prompt := i, prompt
		g.Go(func() error {
			evalPrompt := OnTopicEvaluatorPrompt(prompt)
			conv := attempt.NewConversation()
			conv.WithSystem(OnTopicSystemPrompt(e.cfg.Goal))
			conv.AddTurn(attempt.NewTurn(evalPrompt))
			msgs, err := e.judge.Generate(gctx, conv, 1)
			mu.Lock()
			defer mu.Unlock()
			if err != nil || len(msgs) == 0 {
				scores[i] = 1.0 // Default to on-topic
				return nil
			}
			scores[i] = ParseOnTopicScore(msgs[0].Content)
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return scores, err
	}
	return scores, nil
}
