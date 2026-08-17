package mcpprobe

import (
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// Only codes that reject the REQUEST mean the argument was tested. An internal
// or server-defined error says the server accepted the request and then failed
// while running it — closer to a finding than to a clean result, and recording
// it as a refusal would let a payload that crashed a handler read as one the
// target considered and declined.
func TestClassifyCallError_OnlyRejectionCodesAreRefusals(t *testing.T) {
	cases := []struct {
		code    int64
		refused bool
		what    string
	}{
		{-32602, true, "invalid params"},
		{-32600, true, "invalid request"},
		{-32601, true, "method not found"},
		{-32700, true, "parse error"},
		{-32603, false, "internal error — the handler failed while running"},
		{-32000, false, "server-defined execution failure"},
		{-32050, false, "server-defined execution failure"},
	}
	for _, tc := range cases {
		err := ClassifyCallError(&jsonrpc.Error{Code: tc.code, Message: tc.what})
		got := errors.Is(err, types.ErrCallRefused)
		if got != tc.refused {
			t.Errorf("code %d (%s): refused=%v, want %v", tc.code, tc.what, got, tc.refused)
		}
	}
}

// A transport failure carries no answer from the server at all.
func TestClassifyCallError_TransportFailureIsNotARefusal(t *testing.T) {
	if errors.Is(ClassifyCallError(errors.New("connection reset by peer")), types.ErrCallRefused) {
		t.Error("a transport failure is not a refusal: nothing reached the target")
	}
}
