package main

import (
	"fmt"
	"os"

	"github.com/alecthomas/kong"

	// Import for side effects: register all capabilities via init()
	// Probes
	_ "github.com/praetorian-inc/augustus/internal/probes/apikey"
	_ "github.com/praetorian-inc/augustus/internal/probes/avspamscanning"
	_ "github.com/praetorian-inc/augustus/internal/probes/continuation"
	_ "github.com/praetorian-inc/augustus/internal/probes/dan"
	_ "github.com/praetorian-inc/augustus/internal/probes/encoding"
	_ "github.com/praetorian-inc/augustus/internal/probes/flipattack"
	_ "github.com/praetorian-inc/augustus/internal/probes/goodside"
	_ "github.com/praetorian-inc/augustus/internal/probes/grandma"
	_ "github.com/praetorian-inc/augustus/internal/probes/lmrc"
	_ "github.com/praetorian-inc/augustus/internal/probes/malwaregen"
	_ "github.com/praetorian-inc/augustus/internal/probes/misleading"
	_ "github.com/praetorian-inc/augustus/internal/probes/poetry"
	_ "github.com/praetorian-inc/augustus/internal/probes/smuggling"
	_ "github.com/praetorian-inc/augustus/internal/probes/snowball"
	_ "github.com/praetorian-inc/augustus/internal/probes/suffix"
	_ "github.com/praetorian-inc/augustus/internal/probes/tap"
	_ "github.com/praetorian-inc/augustus/internal/probes/test"

	// Generators
	_ "github.com/praetorian-inc/augustus/internal/generators/anthropic"
	_ "github.com/praetorian-inc/augustus/internal/generators/cohere"
	_ "github.com/praetorian-inc/augustus/internal/generators/function"
	_ "github.com/praetorian-inc/augustus/internal/generators/huggingface"
	_ "github.com/praetorian-inc/augustus/internal/generators/langchain"
	_ "github.com/praetorian-inc/augustus/internal/generators/ollama"
	_ "github.com/praetorian-inc/augustus/internal/generators/openai"
	_ "github.com/praetorian-inc/augustus/internal/generators/replicate"
	_ "github.com/praetorian-inc/augustus/internal/generators/rest"
	_ "github.com/praetorian-inc/augustus/internal/generators/test"

	// Detectors
	_ "github.com/praetorian-inc/augustus/internal/detectors/always"
	_ "github.com/praetorian-inc/augustus/internal/detectors/any"
	_ "github.com/praetorian-inc/augustus/internal/detectors/apikey"
	_ "github.com/praetorian-inc/augustus/internal/detectors/base"
	_ "github.com/praetorian-inc/augustus/internal/detectors/continuation"
	_ "github.com/praetorian-inc/augustus/internal/detectors/dan"
	_ "github.com/praetorian-inc/augustus/internal/detectors/encoding"
	_ "github.com/praetorian-inc/augustus/internal/detectors/fileformats"
	_ "github.com/praetorian-inc/augustus/internal/detectors/flipattack"
	_ "github.com/praetorian-inc/augustus/internal/detectors/goodside"
	_ "github.com/praetorian-inc/augustus/internal/detectors/judge"
	_ "github.com/praetorian-inc/augustus/internal/detectors/knownbadsignatures"
	_ "github.com/praetorian-inc/augustus/internal/detectors/lmrc"
	_ "github.com/praetorian-inc/augustus/internal/detectors/malwaregen"
	_ "github.com/praetorian-inc/augustus/internal/detectors/misleading"
	_ "github.com/praetorian-inc/augustus/internal/detectors/mitigation"
	_ "github.com/praetorian-inc/augustus/internal/detectors/packagehallucination"
	_ "github.com/praetorian-inc/augustus/internal/detectors/productkey"
	_ "github.com/praetorian-inc/augustus/internal/detectors/promptinject"
	_ "github.com/praetorian-inc/augustus/internal/detectors/shields"
	_ "github.com/praetorian-inc/augustus/internal/detectors/snowball"
	_ "github.com/praetorian-inc/augustus/internal/detectors/tap"
	_ "github.com/praetorian-inc/augustus/internal/detectors/unsafecontent"
	_ "github.com/praetorian-inc/augustus/internal/detectors/visualjailbreak"

	// Harnesses
	_ "github.com/praetorian-inc/augustus/internal/harnesses/probewise"

	// Buffs
	_ "github.com/praetorian-inc/augustus/internal/buffs/encoding"
	_ "github.com/praetorian-inc/augustus/internal/buffs/lowercase"
	_ "github.com/praetorian-inc/augustus/internal/buffs/lrl"
	_ "github.com/praetorian-inc/augustus/internal/buffs/paraphrase"
)

func main() {
	// Parse with custom exit handler to enforce proper exit codes:
	// 0 = success, 1 = scan/runtime error, 2 = validation/usage error
	ctx := kong.Parse(&CLI,
		kong.Name("augustus"),
		kong.Description("Augustus - LLM Vulnerability Scanner"),
		kong.UsageOnError(),
		kong.Vars{"version": version},
		kong.Exit(func(code int) {
			// Kong uses code 0 for success, non-zero for parse/validation errors
			// Parse errors should exit with 2 (usage error)
			if code != 0 {
				os.Exit(2)
			}
			os.Exit(0)
		}),
	)

	// Run the command - runtime/scan errors exit with 1
	err := ctx.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
