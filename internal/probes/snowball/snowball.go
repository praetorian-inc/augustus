// Package snowball provides probes for testing LLM hallucination snowballing behavior.
//
// These probes ask models questions with impossible or wrong premises to see if
// they "snowball" into generating false claims rather than admitting uncertainty.
//
// Based on research: https://arxiv.org/abs/2305.13534
// "Hallucination Snowballing in Language Models"
//
// Python garak equivalent: garak.probes.snowball
package snowball

import (
	_ "embed"
	"encoding/json"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

//go:embed data/graph_connectivity.json
var graphConnectivityData []byte

//go:embed data/primality_testing.json
var primalityTestingData []byte

//go:embed data/senator_search.json
var senatorSearchData []byte

// PrimalityEntry represents a single entry from primality_testing.json
type PrimalityEntry struct {
	Question string `json:"question"`
	Number   int    `json:"number"`
	Answer   bool   `json:"answer"` // Always true in this dataset - these ARE prime
}

func init() {
	probes.Register("snowball.GraphConnectivityFull", NewGraphConnectivityFull)
	probes.Register("snowball.GraphConnectivity", NewGraphConnectivity)
	probes.Register("snowball.PrimesFull", NewPrimesFull)
	probes.Register("snowball.Primes", NewPrimes)
	probes.Register("snowball.SenatorsFull", NewSenatorsFull)
	probes.Register("snowball.Senators", NewSenators)
}

// ----------------------------------------------------------------------------
// GraphConnectivity Probes
// ----------------------------------------------------------------------------

// GraphConnectivityFull asks about impossible flight routings (all 500 prompts).
//
// This probe attempts to catch models generating false claims by asking for a
// solution to an impossible problem, couched as a flight routing question.
// The model should answer "No" since there is no valid route.
type GraphConnectivityFull struct {
	*probes.SimpleProbe
}

// NewGraphConnectivityFull creates a probe with all 500 graph connectivity prompts.
func NewGraphConnectivityFull(_ registry.Config) (probes.Prober, error) {
	var promptList []string
	if err := json.Unmarshal(graphConnectivityData, &promptList); err != nil {
		return nil, err
	}

	return &GraphConnectivityFull{
		SimpleProbe: &probes.SimpleProbe{
			ProbeName:        "snowball.GraphConnectivityFull",
			ProbeDescription: "Probe asking for impossible flight routings (full 500 prompts)",
			ProbeGoal:        "trick the model into saying an impossible flight routing is possible",
			PrimaryDetector:  "snowball.DontStartYes",
			Prompts:          promptList,
		},
	}, nil
}

// GraphConnectivity asks about impossible flight routings (last 100 prompts).
// This is the default active version with limited examples.
type GraphConnectivity struct {
	*probes.SimpleProbe
}

// NewGraphConnectivity creates a probe with the last 100 graph connectivity prompts.
func NewGraphConnectivity(_ registry.Config) (probes.Prober, error) {
	var promptList []string
	if err := json.Unmarshal(graphConnectivityData, &promptList); err != nil {
		return nil, err
	}

	// Take last 100 prompts (matching Python: self.prompts[-100:])
	if len(promptList) > 100 {
		promptList = promptList[len(promptList)-100:]
	}

	return &GraphConnectivity{
		SimpleProbe: &probes.SimpleProbe{
			ProbeName:        "snowball.GraphConnectivity",
			ProbeDescription: "Probe asking for impossible flight routings (limited to 100 examples)",
			ProbeGoal:        "trick the model into saying an impossible flight routing is possible",
			PrimaryDetector:  "snowball.DontStartYes",
			Prompts:          promptList,
		},
	}, nil
}

// ----------------------------------------------------------------------------
// Primes Probes
// ----------------------------------------------------------------------------

// PrimesFull asks models to verify prime numbers (all 500 entries).
//
// This probe checks if a model is prone to generating false claims by asking
// if a given number is or isn't prime. All numbers in the dataset ARE prime,
// so the correct answer is "Yes". Hallucinating models will say "No".
type PrimesFull struct {
	*probes.SimpleProbe
}

// NewPrimesFull creates a probe with all 500 primality testing prompts.
func NewPrimesFull(_ registry.Config) (probes.Prober, error) {
	var entries []PrimalityEntry
	if err := json.Unmarshal(primalityTestingData, &entries); err != nil {
		return nil, err
	}

	promptList := make([]string, len(entries))
	for i, entry := range entries {
		promptList[i] = entry.Question
	}

	return &PrimesFull{
		SimpleProbe: &probes.SimpleProbe{
			ProbeName:        "snowball.PrimesFull",
			ProbeDescription: "Ask model to check a list of higher primes (full 500 prompts)",
			ProbeGoal:        "trick the model into saying a prime number isn't prime",
			PrimaryDetector:  "snowball.DontStartNo",
			Prompts:          promptList,
		},
	}, nil
}

// Primes asks models to verify prime numbers (last 100 entries).
type Primes struct {
	*probes.SimpleProbe
}

// NewPrimes creates a probe with the last 100 primality testing prompts.
func NewPrimes(_ registry.Config) (probes.Prober, error) {
	var entries []PrimalityEntry
	if err := json.Unmarshal(primalityTestingData, &entries); err != nil {
		return nil, err
	}

	// Take last 100 entries (matching Python: self.prompts[-100:])
	if len(entries) > 100 {
		entries = entries[len(entries)-100:]
	}

	promptList := make([]string, len(entries))
	for i, entry := range entries {
		promptList[i] = entry.Question
	}

	return &Primes{
		SimpleProbe: &probes.SimpleProbe{
			ProbeName:        "snowball.Primes",
			ProbeDescription: "Ask model to check a list of higher primes (limited to 100 examples)",
			ProbeGoal:        "trick the model into saying a prime number isn't prime",
			PrimaryDetector:  "snowball.DontStartNo",
			Prompts:          promptList,
		},
	}, nil
}

// ----------------------------------------------------------------------------
// Senators Probes
// ----------------------------------------------------------------------------

// SenatorsFull asks about fictitious senators (all 500 prompts).
//
// This probe attempts to find generators prone to generating false claims by
// requesting the name of a US senator given constraints for which there isn't
// a senator. All questions have the answer "No" - no such senator exists.
type SenatorsFull struct {
	*probes.SimpleProbe
}

// NewSenatorsFull creates a probe with all 500 senator search prompts.
func NewSenatorsFull(_ registry.Config) (probes.Prober, error) {
	var promptList []string
	if err := json.Unmarshal(senatorSearchData, &promptList); err != nil {
		return nil, err
	}

	return &SenatorsFull{
		SimpleProbe: &probes.SimpleProbe{
			ProbeName:        "snowball.SenatorsFull",
			ProbeDescription: "Asking for senators that don't exist (full 500 prompts)",
			ProbeGoal:        "trick the model into saying a fictitious senator exists",
			PrimaryDetector:  "snowball.DontStartYes",
			Prompts:          promptList,
		},
	}, nil
}

// Senators asks about fictitious senators (last 100 prompts).
type Senators struct {
	*probes.SimpleProbe
}

// NewSenators creates a probe with the last 100 senator search prompts.
func NewSenators(_ registry.Config) (probes.Prober, error) {
	var promptList []string
	if err := json.Unmarshal(senatorSearchData, &promptList); err != nil {
		return nil, err
	}

	// Take last 100 prompts (matching Python: self.prompts[-100:])
	if len(promptList) > 100 {
		promptList = promptList[len(promptList)-100:]
	}

	return &Senators{
		SimpleProbe: &probes.SimpleProbe{
			ProbeName:        "snowball.Senators",
			ProbeDescription: "Asking for senators that don't exist (limited to 100 examples)",
			ProbeGoal:        "trick the model into saying a fictitious senator exists",
			PrimaryDetector:  "snowball.DontStartYes",
			Prompts:          promptList,
		},
	}, nil
}
