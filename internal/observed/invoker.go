package observed

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/types"
)

// Wrap returns a ToolInvoker that records every response into the store under
// the given identity, then behaves exactly as the one it wraps.
//
// Recording is a decorator rather than a call at each invocation site on
// purpose. A scan makes tool calls from recon modules and from every probe; a
// store fed by hand would depend on each of those remembering to feed it, and
// the failure mode of forgetting is silent — a parameter that could have been
// filled from a response simply never is, and the tool reports as untestable
// for a reason nothing in the output explains. Wrapping the interface makes
// that impossible to get wrong, and callers need no changes at all.
//
// A nil store returns the invoker unchanged, so recording is opt-in and its
// absence costs nothing.
func Wrap(inv types.ToolInvoker, s *Store, identity string) types.ToolInvoker {
	if inv == nil || s == nil {
		return inv
	}
	return &recorder{inner: inv, store: s, identity: identity}
}

type recorder struct {
	inner    types.ToolInvoker
	store    *Store
	identity string
}

func (r *recorder) ListTools(ctx context.Context) ([]map[string]any, error) {
	return r.inner.ListTools(ctx)
}

// CallTool forwards the call and records whatever came back.
//
// A tool-level error response is recorded too. A rejection often names what the
// server would have accepted, and those values are as usable as any returned by
// a success — frequently more so, because a rejection is what a placeholder
// argument provokes. Only a transport failure, which carries no payload,
// records nothing.
func (r *recorder) CallTool(ctx context.Context, name string, args map[string]any) (types.ToolResult, error) {
	res, err := r.inner.CallTool(ctx, name, args)
	if err == nil {
		// The arguments go in with the response. A server that echoes its input
		// would otherwise fill the store with the scanner's own placeholders, and
		// since the newest value wins they would outrank the identifiers the
		// target genuinely handed out.
		r.store.RecordCall(r.identity, name, args, res)
	}
	return res, err
}
