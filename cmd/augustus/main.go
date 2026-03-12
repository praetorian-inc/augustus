package main

import (
	"fmt"
	"os"

	"github.com/alecthomas/kong"

	// Register all built-in capabilities (probes, generators, detectors, buffs, harnesses).
	_ "github.com/praetorian-inc/augustus/pkg/register"
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
