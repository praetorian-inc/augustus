package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/alecthomas/kong"

	// Register all built-in capabilities (probes, generators, detectors, buffs, harnesses).
	_ "github.com/praetorian-inc/augustus/pkg/register"
)

// exitCodeProbesErrored is returned when a scan completed but one or more probes
// errored before producing a verdict (auth failure, 404, timeout). It is kept
// distinct from a runtime error (1) and a clean run (0) so a broken scan — one
// that carries no signal about the target — is detectable by automation (LAB-4316).
const exitCodeProbesErrored = 3

func main() {
	// Parse with custom exit handler to enforce proper exit codes:
	// 0 = success, 1 = scan/runtime error, 2 = validation/usage error,
	// 3 = scan completed but probes errored (no verdict).
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

	if shouldShowBanner(ctx.Command()) {
		printBanner()
	}

	// Run the command - runtime/scan errors exit with 1
	err := ctx.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		// A scan whose only failure is errored probes gets a distinct exit code
		// so it is not mistaken for a clean pass or a generic failure. If an
		// operational error (e.g. a failed cleanup hook) is joined alongside it,
		// that runtime failure takes precedence and we exit 1.
		if onlyProbesErrored(err) {
			os.Exit(exitCodeProbesErrored)
		}
		os.Exit(1)
	}
}

// onlyProbesErrored reports whether err represents solely the errored-probes
// signal, with no operational error joined alongside it. errors.Join exposes
// Unwrap() []error; if any branch is a non-sentinel error, a runtime failure is
// also present and must take precedence over the errored-probes exit code.
func onlyProbesErrored(err error) bool {
	if err == nil || !errors.Is(err, errProbesErrored) {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range joined.Unwrap() {
			if !errors.Is(e, errProbesErrored) {
				return false
			}
		}
	}
	return true
}
