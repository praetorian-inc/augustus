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
// working connection, in answer to a request the server parsed. But arriving is
// not the same as being REFUSED, and only refusal means the argument was tested.
//
// Only codes that reject the REQUEST count:
//
//	-32700 parse error       -32600 invalid request
//	-32601 method not found  -32602 invalid params
//
// Each says the server declined to act on what it was given — a completed test
// with a negative result.
//
// -32603 (internal error) and the server-defined range (-32000..-32099) say the
// opposite: the server accepted the request and then something went wrong while
// running it. Treating those as refusals would let a payload that CRASHED a
// handler be recorded as an argument the target considered and rejected, which
// is both false and exactly backwards — a handler failing on our input is closer
// to a finding than to a clean result. They stay errors, so they surface as
// untested rather than as a pass.
//
// A dropped connection, a timeout or a TLS failure carries no answer at all and
// is left as the plain error it is.
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
	if !rejectsRequest(wire.Code) {
		return err
	}
	return fmt.Errorf("%w (JSON-RPC %d): %w", types.ErrCallRefused, wire.Code, err)
}

// rejectsRequest reports whether a JSON-RPC error code means the server declined
// to act on the request, as opposed to failing while carrying it out.
func rejectsRequest(code int64) bool {
	switch code {
	case -32700, // parse error
		-32600, // invalid request
		-32601, // method not found
		-32602: // invalid params
		return true
	}
	return false
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
		ensureMetadata(a)
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
	ensureMetadata(a)
	a.Metadata[attempt.MetadataKeyNotTested] = true
	a.Metadata[attempt.MetadataKeyNotTestedReason] = reason
}

// ensureMetadata makes an attempt's metadata map writable.
//
// attempt.New allocates it, so this only matters for an Attempt built as a zero
// value — which tests do. Recording an outcome must never be the thing that
// panics: the whole point of these helpers is that the scan can say what
// happened, and a nil map turns "we could not test this" into a stack trace.
func ensureMetadata(a *attempt.Attempt) {
	if a.Metadata == nil {
		a.Metadata = make(map[string]any)
	}
}
