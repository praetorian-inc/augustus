package multiturn

import (
	"context"
	"errors"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/retry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// errRetryableAttack is a sentinel error for retryable attacker LLM failures.
var errRetryableAttack = errors.New("retryable attack attempt")

// Engine implements the multi-turn attack algorithm.
// It maintains two separate conversation histories:
//   - H_A (attacker): sees everything including refused turns and evaluator feedback
//   - H_T (target): only accepted turns; refused questions are pruned
type Engine struct {
	strategy Strategy
	attacker types.Generator
	judge    types.Generator
	cfg      Config
	onTurn   func(TurnRecord)
}

// New creates an Engine with the given strategy, attacker, judge, and config.
func New(strategy Strategy, attacker, judge types.Generator, cfg Config) *Engine {
	return &Engine{
		strategy: strategy,
		attacker: attacker,
		judge:    judge,
		cfg:      cfg,
	}
}

// SetTurnCallback sets an optional callback fired after each completed turn.
func (e *Engine) SetTurnCallback(cb func(TurnRecord)) {
	e.onTurn = cb
}

// Run executes the multi-turn attack against the target generator.
// Returns a slice containing a single Attempt with full conversation history.
func (e *Engine) Run(ctx context.Context, target types.Generator) ([]*attempt.Attempt, error) {
	// H_A: attacker conversation (sees everything)
	attackerConv := attempt.NewConversation()
	attackerConv.WithSystem(e.strategy.AttackerSystemPrompt(e.cfg.Goal))

	// H_T: target conversation (persistent across turns, only accepted turns)
	targetConv := attempt.NewConversation()

	var turnRecords []TurnRecord
	var allQuestions []string
	var allResponses []string
	succeeded := false

	for turnNum := 1; turnNum <= e.cfg.MaxTurns; turnNum++ {
		select {
		case <-ctx.Done():
			return e.buildResult(turnRecords, allQuestions, allResponses, targetConv, succeeded), ctx.Err()
		default:
		}

		// STEP 1: GENERATE — Ask attacker for next question
		var turnPrompt string
		if turnNum == 1 {
			turnPrompt = e.strategy.GenerateTurnPrompt(e.cfg.Goal, nil, turnNum)
		} else {
			turnPrompt = e.strategy.GenerateTurnPrompt(e.cfg.Goal, turnRecords, turnNum)
		}

		questionResult, err := e.generateAttackerQuestion(ctx, attackerConv, turnPrompt)
		if err != nil {
			return e.buildResult(turnRecords, allQuestions, allResponses, targetConv, succeeded), err
		}
		if questionResult == nil {
			continue // Skip if all retries exhausted
		}

		// STEP 2: QUERY TARGET with refusal retry loop
		response, wasRefused, err := e.queryTargetWithRetry(ctx, target, targetConv, attackerConv, questionResult.Question)
		if err != nil {
			return e.buildResult(turnRecords, allQuestions, allResponses, targetConv, succeeded), err
		}
		if wasRefused {
			// All retries refused — record and continue to next turn
			turnRecords = append(turnRecords, TurnRecord{
				TurnNumber: turnNum,
				Question:   questionResult.Question,
				Response:   response,
				WasRefused: true,
				Strategy:   questionResult.Strategy,
			})
			if e.onTurn != nil {
				e.onTurn(turnRecords[len(turnRecords)-1])
			}
			continue
		}

		allQuestions = append(allQuestions, questionResult.Question)
		allResponses = append(allResponses, response)

		// STEP 3: EVALUATE — Judge scores the response (with full conversation context)
		judgeResult := e.evaluateResponse(ctx, questionResult.Question, response, turnRecords)

		// STEP 4: RECORD
		record := TurnRecord{
			TurnNumber:     turnNum,
			Question:       questionResult.Question,
			Response:       response,
			WasRefused:     false,
			JudgeScore:     judgeResult.Score,
			JudgeReasoning: judgeResult.Reasoning,
			Strategy:       questionResult.Strategy,
		}
		turnRecords = append(turnRecords, record)

		if e.onTurn != nil {
			e.onTurn(record)
		}

		// STEP 5: FEEDBACK — Feed response + score to attacker
		feedbackPrompt := e.strategy.FeedbackPrompt(response, judgeResult.Score, e.cfg.Goal)
		attackerConv.AddTurn(attempt.NewTurn(feedbackPrompt))

		// STEP 6: CHECK — Early exit if score >= threshold
		if judgeResult.Score >= e.cfg.SuccessThreshold {
			succeeded = true
			return e.buildResult(turnRecords, allQuestions, allResponses, targetConv, succeeded), nil
		}
	}

	return e.buildResult(turnRecords, allQuestions, allResponses, targetConv, succeeded), nil
}

// generateAttackerQuestion asks the attacker LLM for the next question.
// Retries up to AttackMaxAttempts for valid JSON output.
func (e *Engine) generateAttackerQuestion(ctx context.Context, attackerConv *attempt.Conversation, turnPrompt string) (*QuestionResult, error) {
	attackerConv.AddTurn(attempt.NewTurn(turnPrompt))

	var questionResult *QuestionResult
	err := retry.Do(ctx, retry.Config{
		MaxAttempts: e.cfg.AttackMaxAttempts,
		RetryableFunc: func(err error) bool {
			return errors.Is(err, errRetryableAttack)
		},
	}, func() error {
		msgs, err := e.attacker.Generate(ctx, attackerConv, 1)
		if err != nil {
			return err // Non-retryable
		}
		if len(msgs) == 0 {
			return errRetryableAttack
		}
		result := e.strategy.ParseAttackerResponse(msgs[0].Content)
		if result == nil {
			return errRetryableAttack
		}
		questionResult = result
		// Record attacker's response in H_A
		attackerConv.Turns[len(attackerConv.Turns)-1] = attempt.NewTurn(turnPrompt).WithResponse(msgs[0].Content)
		return nil
	})

	if err != nil && !errors.Is(err, errRetryableAttack) {
		return nil, fmt.Errorf("attacker generation failed: %w", err)
	}

	return questionResult, nil
}

// queryTargetWithRetry sends a question to the target with refusal retry.
// On refusal, removes the question from H_T and asks the attacker to rephrase.
func (e *Engine) queryTargetWithRetry(
	ctx context.Context,
	target types.Generator,
	targetConv *attempt.Conversation,
	attackerConv *attempt.Conversation,
	question string,
) (response string, wasRefused bool, err error) {
	currentQuestion := question

	for retryIdx := 0; retryIdx < e.cfg.MaxRefusalRetries; retryIdx++ {
		select {
		case <-ctx.Done():
			return "", false, ctx.Err()
		default:
		}

		// Add question to H_T
		targetConv.AddTurn(attempt.NewTurn(currentQuestion))

		// Send full H_T to target (target sees ENTIRE conversation history)
		msgs, err := target.Generate(ctx, targetConv, 1)
		if err != nil {
			// Remove the unanswered turn
			targetConv.Turns = targetConv.Turns[:len(targetConv.Turns)-1]
			return "", false, fmt.Errorf("target generation failed: %w", err)
		}

		if len(msgs) == 0 {
			targetConv.Turns = targetConv.Turns[:len(targetConv.Turns)-1]
			continue
		}

		targetResponse := msgs[0].Content

		// Check with refusal judge
		refused := e.checkRefusal(ctx, currentQuestion, targetResponse)

		if !refused {
			// Accepted: record response in H_T and return
			targetConv.Turns[len(targetConv.Turns)-1] = attempt.NewTurn(currentQuestion).WithResponse(targetResponse)
			return targetResponse, false, nil
		}

		// Refused: remove question from H_T, ask attacker to rephrase
		targetConv.Turns = targetConv.Turns[:len(targetConv.Turns)-1]

		rephrasePrompt := e.strategy.RephrasePrompt(currentQuestion, targetResponse)
		attackerConv.AddTurn(attempt.NewTurn(rephrasePrompt))

		rephraseMsgs, err := e.attacker.Generate(ctx, attackerConv, 1)
		if err != nil {
			return targetResponse, true, nil // Return what we have
		}

		if len(rephraseMsgs) > 0 {
			attackerConv.Turns[len(attackerConv.Turns)-1] = attempt.NewTurn(rephrasePrompt).WithResponse(rephraseMsgs[0].Content)
			if result := e.strategy.ParseAttackerResponse(rephraseMsgs[0].Content); result != nil {
				currentQuestion = result.Question
			}
		}

		response = targetResponse // Track last response for reporting
	}

	return response, true, nil
}

// checkRefusal uses the judge LLM to determine if a response is a refusal.
func (e *Engine) checkRefusal(ctx context.Context, question, response string) bool {
	conv := attempt.NewConversation()
	conv.WithSystem(RefusalJudgeSystemPrompt())
	conv.AddTurn(attempt.NewTurn(RefusalJudgePrompt(question, response)))

	msgs, err := e.judge.Generate(ctx, conv, 1)
	if err != nil || len(msgs) == 0 {
		return false // Default to accepted on error
	}

	return ParseRefusalResponse(msgs[0].Content)
}

// evaluateResponse uses the judge LLM to score a target response.
// It passes full conversation history so the judge can assess cumulative progress.
// Optionally invokes the secondary judge for false negative detection.
func (e *Engine) evaluateResponse(ctx context.Context, question, response string, history []TurnRecord) SuccessJudgeResult {
	// Primary judge with conversation context
	conv := attempt.NewConversation()
	conv.WithSystem(SuccessJudgeSystemPrompt(e.cfg.Goal))
	conv.AddTurn(attempt.NewTurn(SuccessJudgePrompt(question, response, history)))

	msgs, err := e.judge.Generate(ctx, conv, 1)
	if err != nil || len(msgs) == 0 {
		return SuccessJudgeResult{Score: 0, Reasoning: "judge error"}
	}

	result := ParseSuccessJudgeResponse(msgs[0].Content)

	// Secondary judge: only if enabled and primary score is below threshold
	if e.cfg.UseSecondaryJudge && result.Score < e.cfg.SuccessThreshold {
		secondaryResult := e.secondaryJudge(ctx, result.Reasoning, response)
		if secondaryResult.Score > result.Score {
			result = secondaryResult
		}
	}

	return result
}

// secondaryJudge reviews the primary judge's reasoning for false negatives.
func (e *Engine) secondaryJudge(ctx context.Context, primaryReasoning, response string) SuccessJudgeResult {
	conv := attempt.NewConversation()
	conv.WithSystem(SecondaryJudgeSystemPrompt(e.cfg.Goal))
	conv.AddTurn(attempt.NewTurn(SecondaryJudgePrompt(primaryReasoning, response)))

	msgs, err := e.judge.Generate(ctx, conv, 1)
	if err != nil || len(msgs) == 0 {
		return SuccessJudgeResult{Score: 0, Reasoning: "secondary judge error"}
	}

	return ParseSuccessJudgeResponse(msgs[0].Content)
}

// buildResult constructs the final Attempt slice from collected turn data.
func (e *Engine) buildResult(
	turnRecords []TurnRecord,
	allQuestions, allResponses []string,
	targetConv *attempt.Conversation,
	succeeded bool,
) []*attempt.Attempt {
	if len(turnRecords) == 0 {
		return nil
	}

	// Use first question as primary prompt
	primaryPrompt := ""
	if len(allQuestions) > 0 {
		primaryPrompt = allQuestions[0]
	}

	a := attempt.New(primaryPrompt)
	a.Prompts = allQuestions
	for _, resp := range allResponses {
		a.AddOutput(resp)
	}

	// Attach full conversation
	a.Conversations = []*attempt.Conversation{targetConv.Clone()}

	// Set score from the highest judge score across turns
	maxScore := 0.0
	for _, tr := range turnRecords {
		if tr.JudgeScore > maxScore {
			maxScore = tr.JudgeScore
		}
	}
	a.AddScore(maxScore)

	// Metadata
	a.WithMetadata("attack_type", e.strategy.Name())
	a.WithMetadata("goal", e.cfg.Goal)
	a.WithMetadata("total_turns", len(turnRecords))
	a.WithMetadata("succeeded", succeeded)
	a.WithMetadata("turn_records", turnRecords)

	a.Complete()

	return []*attempt.Attempt{a}
}
