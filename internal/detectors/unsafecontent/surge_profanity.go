package unsafecontent

import (
	_ "embed"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/praetorian-inc/augustus/internal/detectors/base"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

//go:embed data/profanity_en.csv
var profanityCSV string

// surgeTerms maps category names to lists of profanity terms.
// Populated at init time from embedded CSV.
var (
	surgeTerms    map[string][]string
	surgeTermsErr error
)

func init() {
	surgeTerms, surgeTermsErr = parseSurgeTerms(profanityCSV)
	if surgeTerms == nil {
		surgeTerms = make(map[string][]string)
	}

	// Register all detectors
	detectors.Register("unsafecontent.SurgeProfanitySexual", NewSurgeProfanitySexual)
	detectors.Register("unsafecontent.SurgeProfanityBodilyFluids", NewSurgeProfanityBodilyFluids)
	detectors.Register("unsafecontent.SurgeProfanitySexualOrientationGender", NewSurgeProfanitySexualOrientationGender)
	detectors.Register("unsafecontent.SurgeProfanityRacialEthnic", NewSurgeProfanityRacialEthnic)
	detectors.Register("unsafecontent.SurgeProfanityMentalDisability", NewSurgeProfanityMentalDisability)
	detectors.Register("unsafecontent.SurgeProfanityPhysicalDisability", NewSurgeProfanityPhysicalDisability)
	detectors.Register("unsafecontent.SurgeProfanityPhysicalAttributes", NewSurgeProfanityPhysicalAttributes)
	detectors.Register("unsafecontent.SurgeProfanityAnimalReferences", NewSurgeProfanityAnimalReferences)
	detectors.Register("unsafecontent.SurgeProfanityReligious", NewSurgeProfanityReligious)
	detectors.Register("unsafecontent.SurgeProfanityPolitical", NewSurgeProfanityPolitical)
}

func parseSurgeTerms(csvData string) (map[string][]string, error) {
	reader := csv.NewReader(strings.NewReader(csvData))

	// Read header
	if _, err := reader.Read(); err != nil {
		return nil, fmt.Errorf("read CSV header: %w", err)
	}

	terms := make(map[string][]string)

	for {
		row, err := reader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("read CSV row: %w", err)
		}

		// CSV columns: text, canonical_form_1, canonical_form_2, canonical_form_3,
		//              category_1, category_2, category_3, severity_rating, severity_description
		if len(row) < 7 {
			continue
		}

		text := row[0]
		category1 := row[4]
		category2 := row[5]
		category3 := row[6]

		// Add term to each category it belongs to
		if category1 != "" {
			terms[category1] = append(terms[category1], text)
		}
		if category2 != "" {
			terms[category2] = append(terms[category2], text)
		}
		if category3 != "" {
			terms[category3] = append(terms[category3], text)
		}
	}

	return terms, nil
}

// newSurgeProfanityDetector creates a detector for the given category.
func newSurgeProfanityDetector(name, description, category string, _ registry.Config) (detectors.Detector, error) {
	if surgeTermsErr != nil {
		return nil, fmt.Errorf("failed to initialize embedded Surge profanity list: %w", surgeTermsErr)
	}

	terms := surgeTerms[category]
	if len(terms) == 0 {
		return nil, fmt.Errorf("no terms found for category: %s", category)
	}

	return base.NewSubstringDetector(name, description, terms, base.WithMatchType("word"))
}

// NewSurgeProfanitySexual creates a detector for sexual anatomy / sexual acts.
func NewSurgeProfanitySexual(cfg registry.Config) (detectors.Detector, error) {
	return newSurgeProfanityDetector(
		"unsafecontent.SurgeProfanitySexual",
		"Surge AI profanity list: sexual anatomy / sexual acts",
		"sexual anatomy / sexual acts",
		cfg,
	)
}

// NewSurgeProfanityBodilyFluids creates a detector for bodily fluids / excrement.
func NewSurgeProfanityBodilyFluids(cfg registry.Config) (detectors.Detector, error) {
	return newSurgeProfanityDetector(
		"unsafecontent.SurgeProfanityBodilyFluids",
		"Surge AI profanity list: bodily fluids / excrement",
		"bodily fluids / excrement",
		cfg,
	)
}

// NewSurgeProfanitySexualOrientationGender creates a detector for sexual orientation / gender.
func NewSurgeProfanitySexualOrientationGender(cfg registry.Config) (detectors.Detector, error) {
	return newSurgeProfanityDetector(
		"unsafecontent.SurgeProfanitySexualOrientationGender",
		"Surge AI profanity list: sexual orientation / gender",
		"sexual orientation / gender",
		cfg,
	)
}

// NewSurgeProfanityRacialEthnic creates a detector for racial / ethnic slurs.
func NewSurgeProfanityRacialEthnic(cfg registry.Config) (detectors.Detector, error) {
	return newSurgeProfanityDetector(
		"unsafecontent.SurgeProfanityRacialEthnic",
		"Surge AI profanity list: racial / ethnic slurs",
		"racial / ethnic slurs",
		cfg,
	)
}

// NewSurgeProfanityMentalDisability creates a detector for mental disability slurs.
func NewSurgeProfanityMentalDisability(cfg registry.Config) (detectors.Detector, error) {
	return newSurgeProfanityDetector(
		"unsafecontent.SurgeProfanityMentalDisability",
		"Surge AI profanity list: mental disability",
		"mental disability",
		cfg,
	)
}

// NewSurgeProfanityPhysicalDisability creates a detector for physical disability slurs.
func NewSurgeProfanityPhysicalDisability(cfg registry.Config) (detectors.Detector, error) {
	return newSurgeProfanityDetector(
		"unsafecontent.SurgeProfanityPhysicalDisability",
		"Surge AI profanity list: physical disability",
		"physical disability",
		cfg,
	)
}

// NewSurgeProfanityPhysicalAttributes creates a detector for physical attributes slurs.
func NewSurgeProfanityPhysicalAttributes(cfg registry.Config) (detectors.Detector, error) {
	return newSurgeProfanityDetector(
		"unsafecontent.SurgeProfanityPhysicalAttributes",
		"Surge AI profanity list: physical attributes",
		"physical attributes",
		cfg,
	)
}

// NewSurgeProfanityAnimalReferences creates a detector for animal references.
func NewSurgeProfanityAnimalReferences(cfg registry.Config) (detectors.Detector, error) {
	return newSurgeProfanityDetector(
		"unsafecontent.SurgeProfanityAnimalReferences",
		"Surge AI profanity list: animal references",
		"animal references",
		cfg,
	)
}

// NewSurgeProfanityReligious creates a detector for religious offense.
func NewSurgeProfanityReligious(cfg registry.Config) (detectors.Detector, error) {
	return newSurgeProfanityDetector(
		"unsafecontent.SurgeProfanityReligious",
		"Surge AI profanity list: religious offense",
		"religious offense",
		cfg,
	)
}

// NewSurgeProfanityPolitical creates a detector for political profanity.
func NewSurgeProfanityPolitical(cfg registry.Config) (detectors.Detector, error) {
	return newSurgeProfanityDetector(
		"unsafecontent.SurgeProfanityPolitical",
		"Surge AI profanity list: political",
		"political",
		cfg,
	)
}
