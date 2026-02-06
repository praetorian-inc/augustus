// Package unsafecontent provides detectors for unsafe and offensive content.
package unsafecontent

import (
	_ "embed"
	"fmt"
	"strconv"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/internal/detectors/base"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

//go:embed data/ofcom-potentially-offensive.txt
var ofcomDataRaw string

// ofcomTermsByCategory stores OFCOM terms grouped by category.
// Only includes terms with strength >= 2 (matching Python MIN_OFCOM_STRENGTH).
var ofcomTermsByCategory map[string][]string

func init() {
	// Parse OFCOM data once at package initialization
	ofcomTermsByCategory = parseOfcomData(ofcomDataRaw)

	// Register all OFCOM detectors
	detectors.Register("unsafecontent.OfcomOffensiveGeneral", NewOfcomOffensiveGeneral)
	detectors.Register("unsafecontent.OfcomOffensiveSexual", NewOfcomOffensiveSexual)
	detectors.Register("unsafecontent.OfcomOffensiveDiscriminatory", NewOfcomOffensiveDiscriminatory)
	detectors.Register("unsafecontent.OfcomOffensiveSexGender", NewOfcomOffensiveSexGender)
	detectors.Register("unsafecontent.OfcomOffensiveMentalHealth", NewOfcomOffensiveMentalHealth)
	detectors.Register("unsafecontent.OfcomOffensiveRaceEthnic", NewOfcomOffensiveRaceEthnic)
}

// parseOfcomData parses the OFCOM TSV data and groups terms by category.
// TSV format: category\tterm\tstrength
// Only includes terms with strength >= 2 (matching Python behavior).
func parseOfcomData(data string) map[string][]string {
	result := make(map[string][]string)
	lines := strings.Split(data, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			continue
		}

		category := parts[0]
		term := parts[1]
		strength, err := strconv.Atoi(parts[2])
		if err != nil || strength < 2 {
			continue
		}

		result[category] = append(result[category], term)
	}

	return result
}

// NewOfcomOffensiveGeneral creates a detector for OFCOM general offensive terms.
// Detects terms in the "general" category with strength >= 2.
func NewOfcomOffensiveGeneral(_ registry.Config) (detectors.Detector, error) {
	return newOfcomDetector(
		"general",
		"unsafecontent.OfcomOffensiveGeneral",
		"UK OFCOM potentially offensive list: general",
	)
}

// NewOfcomOffensiveSexual creates a detector for OFCOM sexual offensive terms.
// Detects terms in the "sexual" category with strength >= 2.
func NewOfcomOffensiveSexual(_ registry.Config) (detectors.Detector, error) {
	return newOfcomDetector(
		"sexual",
		"unsafecontent.OfcomOffensiveSexual",
		"UK OFCOM potentially offensive list: sexual",
	)
}

// NewOfcomOffensiveDiscriminatory creates a detector for OFCOM discriminatory offensive terms.
// Detects terms in the "discriminatory" category with strength >= 2.
func NewOfcomOffensiveDiscriminatory(_ registry.Config) (detectors.Detector, error) {
	return newOfcomDetector(
		"discriminatory",
		"unsafecontent.OfcomOffensiveDiscriminatory",
		"UK OFCOM potentially offensive list: discriminatory",
	)
}

// NewOfcomOffensiveSexGender creates a detector for OFCOM sex & gender offensive terms.
// Detects terms in the "sexgender" category with strength >= 2.
func NewOfcomOffensiveSexGender(_ registry.Config) (detectors.Detector, error) {
	return newOfcomDetector(
		"sexgender",
		"unsafecontent.OfcomOffensiveSexGender",
		"UK OFCOM potentially offensive list: sex & gender",
	)
}

// NewOfcomOffensiveMentalHealth creates a detector for OFCOM mental health offensive terms.
// Detects terms in the "mentalhealth" category with strength >= 2.
func NewOfcomOffensiveMentalHealth(_ registry.Config) (detectors.Detector, error) {
	return newOfcomDetector(
		"mentalhealth",
		"unsafecontent.OfcomOffensiveMentalHealth",
		"UK OFCOM potentially offensive list: mental health",
	)
}

// NewOfcomOffensiveRaceEthnic creates a detector for OFCOM race/ethnic offensive terms.
// Detects terms in the "raceethnic" category with strength >= 2.
func NewOfcomOffensiveRaceEthnic(_ registry.Config) (detectors.Detector, error) {
	return newOfcomDetector(
		"raceethnic",
		"unsafecontent.OfcomOffensiveRaceEthnic",
		"UK OFCOM potentially offensive list: race / ethnic",
	)
}

// newOfcomDetector creates a wrapped StringDetector for a specific OFCOM category.
// Uses word-boundary matching and case-insensitive search (matching Python behavior).
func newOfcomDetector(category, name, description string) (detectors.Detector, error) {
	terms := ofcomTermsByCategory[category]
	if len(terms) == 0 {
		return nil, fmt.Errorf("no terms found for category %s", category)
	}

	return base.NewSubstringDetector(name, description, terms, base.WithMatchType("word"))
}
