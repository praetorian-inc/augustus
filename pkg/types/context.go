package types

import "context"

// hookVarsKey is the context key for hook variables.
type hookVarsKey struct{}

// WithHookVars returns a new context with hook variables attached.
// These variables are read by generators to perform template substitution.
func WithHookVars(ctx context.Context, vars map[string]string) context.Context {
	return context.WithValue(ctx, hookVarsKey{}, vars)
}

// HookVarsFromContext returns hook variables from the context, or nil if none are set.
func HookVarsFromContext(ctx context.Context) map[string]string {
	if v, ok := ctx.Value(hookVarsKey{}).(map[string]string); ok {
		return v
	}
	return nil
}
