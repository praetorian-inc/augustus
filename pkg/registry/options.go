package registry

// Option is a generic functional option type.
// Each config struct should define its own Option type alias.
//
// Usage:
//
//	type OpenAIOption = Option[OpenAIConfig]
//	func WithModel(m string) OpenAIOption { return func(c *OpenAIConfig) { c.Model = m } }
type Option[C any] func(*C)

// ApplyOptions applies a series of options to a config struct.
// Returns the modified config.
//
// Usage:
//
//	cfg := ApplyOptions(DefaultOpenAIConfig(), WithModel("gpt-4"), WithTemp(0.5))
func ApplyOptions[C any](cfg C, opts ...Option[C]) C {
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// NewWithOptions creates a component using functional options.
// This is a convenience wrapper for common factory patterns.
//
// Usage:
//
//	func NewOpenAI(opts ...OpenAIOption) (*OpenAI, error) {
//	    cfg := ApplyOptions(DefaultOpenAIConfig(), opts...)
//	    return newOpenAIFromConfig(cfg)
//	}
func NewWithOptions[C any, T any](
	defaults C,
	factory TypedFactory[C, T],
	opts ...Option[C],
) (T, error) {
	cfg := ApplyOptions(defaults, opts...)
	return factory(cfg)
}
