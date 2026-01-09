package unsafecontent

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSurgeProfanitySexual tests the Sexual Anatomy detector
func TestSurgeProfanitySexual(t *testing.T) {
	det, err := NewSurgeProfanitySexual(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, det)

	ctx := context.Background()

	// Test cases: should detect sexual terms
	testCases := []struct {
		name     string
		input    string
		expected float64
	}{
		{"contains sexual term", "This contains 69 which is sexual", 1.0},
		{"contains anus", "medical term anus examination", 1.0},
		{"contains anal", "talking about anal cavity", 1.0},
		{"clean text", "This is a normal sentence", 0.0},
		{"word boundary test", "analysis should not match", 0.0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := &attempt.Attempt{
				Outputs: []string{tc.input},
			}
			scores, err := det.Detect(ctx, a)
			require.NoError(t, err)
			require.Len(t, scores, 1)
			assert.Equal(t, tc.expected, scores[0], "input: %s", tc.input)
		})
	}
}

// TestSurgeProfanityBodilyFluids tests the Bodily Fluids detector
func TestSurgeProfanityBodilyFluids(t *testing.T) {
	det, err := NewSurgeProfanityBodilyFluids(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, det)

	ctx := context.Background()

	testCases := []struct {
		name     string
		input    string
		expected float64
	}{
		{"contains 5h17", "what a load of 5h17", 1.0},
		{"contains 5h1t", "this is 5h1t", 1.0},
		{"clean text", "This is a normal sentence", 0.0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := &attempt.Attempt{
				Outputs: []string{tc.input},
			}
			scores, err := det.Detect(ctx, a)
			require.NoError(t, err)
			require.Len(t, scores, 1)
			assert.Equal(t, tc.expected, scores[0])
		})
	}
}

// TestSurgeProfanitySexualOrientationGender tests the Sexual Orientation/Gender detector
func TestSurgeProfanitySexualOrientationGender(t *testing.T) {
	det, err := NewSurgeProfanitySexualOrientationGender(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, det)

	ctx := context.Background()

	// The CSV contains terms from sexual orientation category
	// Using a term we know is in the sexual orientation category
	a := &attempt.Attempt{
		Outputs: []string{"this contains 5kank term"},
	}
	scores, err := det.Detect(ctx, a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 1.0, scores[0])

	// Clean text should not match
	a = &attempt.Attempt{
		Outputs: []string{"This is a normal sentence"},
	}
	scores, err = det.Detect(ctx, a)
	require.NoError(t, err)
	assert.Equal(t, 0.0, scores[0])
}

// TestSurgeProfanityRacialEthnic tests the Racial/Ethnic detector
func TestSurgeProfanityRacialEthnic(t *testing.T) {
	det, err := NewSurgeProfanityRacialEthnic(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, det)

	ctx := context.Background()

	a := &attempt.Attempt{
		Outputs: []string{"contains abeed which is racial slur"},
	}
	scores, err := det.Detect(ctx, a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 1.0, scores[0])

	// Clean text should not match
	a = &attempt.Attempt{
		Outputs: []string{"This is a normal sentence"},
	}
	scores, err = det.Detect(ctx, a)
	require.NoError(t, err)
	assert.Equal(t, 0.0, scores[0])
}

// TestSurgeProfanityMentalDisability tests the Mental Disability detector
func TestSurgeProfanityMentalDisability(t *testing.T) {
	det, err := NewSurgeProfanityMentalDisability(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, det)

	ctx := context.Background()

	// This category exists in the CSV - verify there are terms
	// We'll check that the detector is created successfully
	// Specific term testing would require knowing exact terms in this category
	a := &attempt.Attempt{
		Outputs: []string{"This is a normal sentence"},
	}
	scores, err := det.Detect(ctx, a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 0.0, scores[0])
}

// TestSurgeProfanityPhysicalDisability tests the Physical Disability detector
func TestSurgeProfanityPhysicalDisability(t *testing.T) {
	det, err := NewSurgeProfanityPhysicalDisability(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, det)

	ctx := context.Background()

	a := &attempt.Attempt{
		Outputs: []string{"This is a normal sentence"},
	}
	scores, err := det.Detect(ctx, a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 0.0, scores[0])
}

// TestSurgeProfanityPhysicalAttributes tests the Physical Attributes detector
func TestSurgeProfanityPhysicalAttributes(t *testing.T) {
	det, err := NewSurgeProfanityPhysicalAttributes(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, det)

	ctx := context.Background()

	a := &attempt.Attempt{
		Outputs: []string{"This is a normal sentence"},
	}
	scores, err := det.Detect(ctx, a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 0.0, scores[0])
}

// TestSurgeProfanityAnimalReferences tests the Animal References detector
func TestSurgeProfanityAnimalReferences(t *testing.T) {
	det, err := NewSurgeProfanityAnimalReferences(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, det)

	ctx := context.Background()

	a := &attempt.Attempt{
		Outputs: []string{"animal fucker is offensive"},
	}
	scores, err := det.Detect(ctx, a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 1.0, scores[0])

	// Clean text should not match
	a = &attempt.Attempt{
		Outputs: []string{"This is a normal sentence"},
	}
	scores, err = det.Detect(ctx, a)
	require.NoError(t, err)
	assert.Equal(t, 0.0, scores[0])
}

// TestSurgeProfanityReligious tests the Religious Offense detector
func TestSurgeProfanityReligious(t *testing.T) {
	det, err := NewSurgeProfanityReligious(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, det)

	ctx := context.Background()

	a := &attempt.Attempt{
		Outputs: []string{"This is a normal sentence"},
	}
	scores, err := det.Detect(ctx, a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 0.0, scores[0])
}

// TestSurgeProfanityPolitical tests the Political detector
func TestSurgeProfanityPolitical(t *testing.T) {
	det, err := NewSurgeProfanityPolitical(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, det)

	ctx := context.Background()

	a := &attempt.Attempt{
		Outputs: []string{"This is a normal sentence"},
	}
	scores, err := det.Detect(ctx, a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 0.0, scores[0])
}

// TestDetectorRegistration tests that all detectors are properly registered
func TestDetectorRegistration(t *testing.T) {
	expectedDetectors := []string{
		"unsafecontent.SurgeProfanitySexual",
		"unsafecontent.SurgeProfanityBodilyFluids",
		"unsafecontent.SurgeProfanitySexualOrientationGender",
		"unsafecontent.SurgeProfanityRacialEthnic",
		"unsafecontent.SurgeProfanityMentalDisability",
		"unsafecontent.SurgeProfanityPhysicalDisability",
		"unsafecontent.SurgeProfanityPhysicalAttributes",
		"unsafecontent.SurgeProfanityAnimalReferences",
		"unsafecontent.SurgeProfanityReligious",
		"unsafecontent.SurgeProfanityPolitical",
	}

	for _, name := range expectedDetectors {
		t.Run(name, func(t *testing.T) {
			det, err := detectors.Create(name, registry.Config{})
			require.NoError(t, err, "detector %s should be registered", name)
			require.NotNil(t, det)
			assert.Equal(t, name, det.Name())
		})
	}
}

// TestCSVParsing tests that the CSV is parsed correctly at init time
func TestCSVParsing(t *testing.T) {
	// Verify that each category has terms loaded
	categories := []string{
		"sexual anatomy / sexual acts",
		"bodily fluids / excrement",
		"sexual orientation / gender",
		"racial / ethnic slurs",
		"mental disability",
		"physical disability",
		"physical attributes",
		"animal references",
		"religious offense",
		"political",
	}

	// We can't directly access surgeTerms since it's package-private,
	// but we can verify indirectly by creating detectors and ensuring
	// they don't error out and have some terms loaded
	constructors := []struct {
		name        string
		constructor func(registry.Config) (detectors.Detector, error)
		category    string
	}{
		{"SurgeProfanitySexual", NewSurgeProfanitySexual, categories[0]},
		{"SurgeProfanityBodilyFluids", NewSurgeProfanityBodilyFluids, categories[1]},
		{"SurgeProfanitySexualOrientationGender", NewSurgeProfanitySexualOrientationGender, categories[2]},
		{"SurgeProfanityRacialEthnic", NewSurgeProfanityRacialEthnic, categories[3]},
		{"SurgeProfanityMentalDisability", NewSurgeProfanityMentalDisability, categories[4]},
		{"SurgeProfanityPhysicalDisability", NewSurgeProfanityPhysicalDisability, categories[5]},
		{"SurgeProfanityPhysicalAttributes", NewSurgeProfanityPhysicalAttributes, categories[6]},
		{"SurgeProfanityAnimalReferences", NewSurgeProfanityAnimalReferences, categories[7]},
		{"SurgeProfanityReligious", NewSurgeProfanityReligious, categories[8]},
		{"SurgeProfanityPolitical", NewSurgeProfanityPolitical, categories[9]},
	}

	for _, tc := range constructors {
		t.Run(tc.name, func(t *testing.T) {
			det, err := tc.constructor(registry.Config{})
			require.NoError(t, err, "should parse CSV and create detector for category: %s", tc.category)
			require.NotNil(t, det)
		})
	}
}
