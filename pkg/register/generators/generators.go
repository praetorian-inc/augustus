// Package generators registers all built-in generator implementations.
//
// Import this package for side effects to populate the global generator registry:
//
//	import _ "github.com/praetorian-inc/augustus/pkg/register/generators"
package generators

import (
	_ "github.com/praetorian-inc/augustus/internal/generators/anthropic"
	_ "github.com/praetorian-inc/augustus/internal/generators/anyscale"
	_ "github.com/praetorian-inc/augustus/internal/generators/azure"
	_ "github.com/praetorian-inc/augustus/internal/generators/bedrock"
	_ "github.com/praetorian-inc/augustus/internal/generators/cohere"
	_ "github.com/praetorian-inc/augustus/internal/generators/deepinfra"
	_ "github.com/praetorian-inc/augustus/internal/generators/fireworks"
	_ "github.com/praetorian-inc/augustus/internal/generators/function"
	_ "github.com/praetorian-inc/augustus/internal/generators/ggml"
	_ "github.com/praetorian-inc/augustus/internal/generators/groq"
	_ "github.com/praetorian-inc/augustus/internal/generators/guardrails"
	_ "github.com/praetorian-inc/augustus/internal/generators/huggingface"
	_ "github.com/praetorian-inc/augustus/internal/generators/langchain"
	_ "github.com/praetorian-inc/augustus/internal/generators/langchainserve"
	_ "github.com/praetorian-inc/augustus/internal/generators/litellm"
	_ "github.com/praetorian-inc/augustus/internal/generators/mistral"
	_ "github.com/praetorian-inc/augustus/internal/generators/nemo"
	_ "github.com/praetorian-inc/augustus/internal/generators/nim"
	_ "github.com/praetorian-inc/augustus/internal/generators/nvcf"
	_ "github.com/praetorian-inc/augustus/internal/generators/ollama"
	_ "github.com/praetorian-inc/augustus/internal/generators/openai"
	_ "github.com/praetorian-inc/augustus/internal/generators/rasa"
	_ "github.com/praetorian-inc/augustus/internal/generators/replicate"
	_ "github.com/praetorian-inc/augustus/internal/generators/rest"
	_ "github.com/praetorian-inc/augustus/internal/generators/test"
	_ "github.com/praetorian-inc/augustus/internal/generators/together"
	_ "github.com/praetorian-inc/augustus/internal/generators/vertex"
	_ "github.com/praetorian-inc/augustus/internal/generators/watsonx"
)
