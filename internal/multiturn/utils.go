package multiturn

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// maxConsecutiveAttackerFailures is the number of consecutive turns where the
// attacker fails to produce valid output before the engine gives up early.
// This prevents burning all MaxTurns when the attacker LLM consistently refuses.
const maxConsecutiveAttackerFailures = 3

// isContextLengthError checks if an error is related to exceeding the model's context window.
func isContextLengthError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "maximum context length") ||
		strings.Contains(msg, "token limit") ||
		strings.Contains(msg, "context_length_exceeded") ||
		strings.Contains(msg, "max_tokens") ||
		strings.Contains(msg, "context window") ||
		strings.Contains(msg, "too many tokens") ||
		strings.Contains(msg, "token count")
}

// estimateTokens returns a rough token count for a string (~4 chars per token).
func estimateTokens(s string) int {
	return (len(s) + 3) / 4
}

// estimateConversationTokens estimates total tokens in a conversation.
func estimateConversationTokens(conv *attempt.Conversation) int {
	total := 0
	if conv.System != nil {
		total += estimateTokens(conv.System.Content)
	}
	for _, turn := range conv.Turns {
		total += estimateTokens(turn.Prompt.Content)
		if turn.Response != nil {
			total += estimateTokens(turn.Response.Content)
		}
	}
	return total
}

// shouldTrimConversation returns true if the estimated token count of the
// conversation exceeds 80% of the context window limit.
func shouldTrimConversation(conv *attempt.Conversation, contextLimit int) bool {
	if contextLimit <= 0 {
		return false
	}
	// Rough estimate: 4 chars per token
	estimatedTokens := 0
	if conv.System != nil {
		estimatedTokens += len(conv.System.Content) / 4
	}
	for _, turn := range conv.Turns {
		estimatedTokens += len(turn.Prompt.Content) / 4
		if turn.Response != nil {
			estimatedTokens += len(turn.Response.Content) / 4
		}
	}
	return estimatedTokens > (contextLimit * 80 / 100)
}

// trimConversation removes the oldest non-system turns to fit within maxTokens.
// It keeps the system prompt and the most recent turns, inserting a truncation
// notice so the attacker LLM knows earlier context was removed.
func trimConversation(conv *attempt.Conversation, maxTokens int) {
	if estimateConversationTokens(conv) <= maxTokens {
		return
	}

	systemTokens := 0
	if conv.System != nil {
		systemTokens = estimateTokens(conv.System.Content)
	}
	// Reserve tokens for system + truncation notice buffer
	budget := maxTokens - systemTokens - 100

	// Walk backwards through turns, accumulating tokens until budget is exhausted
	keepFrom := len(conv.Turns)
	usedTokens := 0
	for i := len(conv.Turns) - 1; i >= 0; i-- {
		turnTokens := estimateTokens(conv.Turns[i].Prompt.Content)
		if conv.Turns[i].Response != nil {
			turnTokens += estimateTokens(conv.Turns[i].Response.Content)
		}
		if usedTokens+turnTokens > budget {
			break
		}
		usedTokens += turnTokens
		keepFrom = i
	}

	// Always keep at least the last turn
	if keepFrom >= len(conv.Turns) {
		keepFrom = len(conv.Turns) - 1
	}

	removed := keepFrom
	if removed > 0 {
		conv.Turns = conv.Turns[keepFrom:]
		// Prepend truncation notice to the first remaining turn
		notice := fmt.Sprintf("[CONTEXT TRUNCATED: %d earlier messages were removed to fit within the model's context window. Continue the attack based on the remaining conversation history and the GOAL in your system prompt.]", removed)
		conv.Turns[0] = attempt.Turn{
			Prompt: attempt.Message{
				Role:    conv.Turns[0].Prompt.Role,
				Content: notice + "\n\n" + conv.Turns[0].Prompt.Content,
			},
			Response: conv.Turns[0].Response,
		}
	}
}

// base64Chars is a lookup table for base64 alphabet characters.
var base64Chars [256]bool

func init() {
	for _, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" {
		base64Chars[c] = true
	}
}

// scrubOutputForHistory strips large base64 blobs from target responses before
// adding them to the conversation history. This prevents token bloat in the
// attacker LLM context.
func scrubOutputForHistory(output string) string {
	// Handle b64_json fields in JSON responses
	if idx := strings.Index(output, `"b64_json"`); idx >= 0 {
		output = scrubB64JSONFields(output)
	}

	// Scan for long runs of base64 characters (>2000 chars)
	return scrubLongBase64Runs(output, 2000)
}

// scrubB64JSONFields replaces "b64_json": "..." values with a redacted placeholder.
var b64JSONFieldPattern = regexp.MustCompile(`"b64_json"\s*:\s*"[^"]*"`)

func scrubB64JSONFields(output string) string {
	return b64JSONFieldPattern.ReplaceAllStringFunc(output, func(match string) string {
		return fmt.Sprintf(`"b64_json": "[binary output redacted; length=%d]"`, len(match))
	})
}

// scrubLongBase64Runs replaces contiguous runs of base64 characters that exceed
// the given threshold with a redacted placeholder.
func scrubLongBase64Runs(output string, threshold int) string {
	var result strings.Builder
	result.Grow(len(output))

	i := 0
	for i < len(output) {
		if base64Chars[output[i]] {
			// Found a base64 character — measure the run
			start := i
			for i < len(output) && base64Chars[output[i]] {
				i++
			}
			runLen := i - start
			if runLen >= threshold {
				result.WriteString(fmt.Sprintf("[binary output redacted; length=%d]", runLen))
			} else {
				result.WriteString(output[start:i])
			}
		} else {
			result.WriteByte(output[i])
			i++
		}
	}
	return result.String()
}

// isClarifyingQuestion detects when the target is asking a clarifying question
// rather than engaging with or refusing the request.
func isClarifyingQuestion(response string) bool {
	lower := strings.ToLower(strings.TrimSpace(response))

	// Short responses ending with ? are likely clarifying questions
	if strings.HasSuffix(strings.TrimSpace(response), "?") && len(response) < 500 {
		for _, marker := range clarifyingMarkers {
			if strings.Contains(lower, marker) {
				return true
			}
		}
	}
	return false
}

var clarifyingMarkers = []string{
	"could you clarify",
	"can you clarify",
	"what do you mean",
	"could you be more specific",
	"can you provide more context",
	"what exactly",
	"which specific",
	"are you asking",
	"do you mean",
	"can you elaborate",
	"could you elaborate",
	"what kind of",
	"what type of",
	"for what purpose",
	"in what context",
}
