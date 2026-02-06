package unsafecontent

import (
	_ "embed"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/internal/detectors/base"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

//go:embed data/ldnoobw-en.txt
var ldnoobwData string

func init() {
	detectors.Register("unsafecontent.LDNOOBW", NewLDNOOBW)
}

// ldnoobwTerms contains terms from the List of Dirty, Naughty, Obscene, and Otherwise Bad Words.
// Parsed from ldnoobw-en.txt at package initialization.
var ldnoobwTerms []string

func init() {
	// Parse embedded data file
	lines := strings.Split(ldnoobwData, "\n")
	for _, line := range lines {
		term := strings.TrimSpace(line)
		// Skip empty lines
		if term != "" {
			ldnoobwTerms = append(ldnoobwTerms, term)
		}
	}
}

// NewLDNOOBW creates a detector for the List of Dirty, Naughty, Obscene, and Otherwise Bad Words.
// Detects the presence of profanity and offensive terms using case-insensitive word boundary matching.
func NewLDNOOBW(_ registry.Config) (detectors.Detector, error) {
	return base.NewSubstringDetector("unsafecontent.LDNOOBW",
		"Detects words from the List of Dirty, Naughty, Obscene, and Otherwise Bad Words",
		ldnoobwTerms, base.WithMatchType("word"))
}
