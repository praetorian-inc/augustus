package mcpprobe

import (
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// ClassifyCallError marks an error the TARGET produced, as distinct from one the
// transport produced.
//
// A JSON-RPC error object can only have come from the server: it arrived over a
// working connection, in answer to a request the server parsed. So the call
// reached the target and the target refused it — a completed test with a
// negative result, not a failure to test. A dropped connection, a timeout or a
// TLS failure carries no such answer and is left as the plain error it is.
//
// The wrapping is additive. The original error is preserved for its message and
// its own chain, so a caller that does not care about the distinction sees
// exactly what it saw before.
func ClassifyCallError(err error) error {
	if err == nil {
		return nil
	}
	var wire *jsonrpc.Error
	if !errors.As(err, &wire) {
		return err
	}
	return fmt.Errorf("%w (JSON-RPC %d): %w", types.ErrCallRefused, wire.Code, err)
}

// RecordCallFailure records the outcome of a tool call that returned an error,
// putting the attempt into the state that describes what actually happened.
//
// Two outcomes, and conflating them is the defect this exists to remove:
//
//	REFUSED   — the call reached the target and the target rejected it. The
//	            argument WAS tested; the answer was no. The attempt completes,
//	            carrying the refusal as its evidence.
//	NOT TESTED — nothing reached the target, or nothing came back. Nothing is
//	            known about the argument. The attempt errors and says so.
//
// Recording a refusal as an error is not a harmless over-report. On a server
// that validates its arguments strictly, most attempts are refusals, so most of
// the scan reads as broken and the operator learns to ignore the error count —
// at which point a genuine "we never tested this" is invisible. Recording a
// failure to test as a pass is the opposite error and the worse one; neither is
// acceptable, which is why they are separated rather than merged in either
// direction.
//
// It returns true when the attempt was TESTED, so a caller can decide whether it
// still has a comparison to draw.
func RecordCallFailure(a *attempt.Attempt, err error) bool {
	if a == nil || err == nil {
		return true
	}
	if errors.Is(err, types.ErrCallRefused) {
		a.Metadata[attempt.MetadataKeyTargetRefused] = true
		a.AddOutput("the target refused the call: " + err.Error())
		a.Complete()
		return true
	}
	MarkNotTested(a, err.Error())
	a.SetError(err)
	return false
}

// MarkNotTested records that an attempt never reached the point of testing
// anything, and why.
//
// The reason is mandatory. An attempt that says only "not tested" moves the
// question from the report to whoever reads it, and the whole purpose of the
// flag is to make the gap answerable from the output.
func MarkNotTested(a *attempt.Attempt, reason string) {
	if a == nil {
		return
	}
	a.Metadata[attempt.MetadataKeyNotTested] = true
	a.Metadata[attempt.MetadataKeyNotTestedReason] = reason
}
