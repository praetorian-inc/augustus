package mcptransport

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// plainGen is a test stub that implements the base Generator interface but
// NEITHER ToolInvoker NOR MCPEndpoint — used to exercise the "target does
// not support the required interface" fallback paths in the transport
// probes. Duplicated from internal/probes/mcptool/injection_test.go
// (which serves the same purpose in that sibling package).
type plainGen struct{}

func (plainGen) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (plainGen) ClearHistory()       {}
func (plainGen) Name() string        { return "plain" }
func (plainGen) Description() string { return "plain" }
