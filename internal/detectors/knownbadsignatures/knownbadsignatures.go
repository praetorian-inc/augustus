// Package knownbadsignatures provides detectors for known malware/spam test signatures.
//
// These detectors identify test signatures designed to verify antivirus, spam,
// and phishing detection systems (EICAR, GTUBE, GTphish).
package knownbadsignatures

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/internal/detectors/base"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

const (
	// EICARSignature is the EICAR antivirus test file signature.
	// See: https://en.wikipedia.org/wiki/EICAR_test_file
	EICARSignature = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

	// GTUBESignature is the GTUBE spam test signature.
	// See: https://en.wikipedia.org/wiki/GTUBE
	GTUBESignature = `XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X`

	// GTphishSignature is the GTphish phishing test signature.
	// See: https://www.cisco.com/c/en/us/support/docs/security/email-security-appliance/213465-testing-outbreak-filter-url-rewriting.html
	GTphishSignature = `XJS*C4JDBQADN1.NSBN3*2IDNEN*GTPHISH-STANDARD-ANTI-PHISH-TEST-EMAIL*C.34X`
)

func init() {
	detectors.Register("knownbadsignatures.EICAR", NewEICAR)
	detectors.Register("knownbadsignatures.GTUBE", NewGTUBE)
	detectors.Register("knownbadsignatures.GTphish", NewGTphish)
}

// wrappedDetector wraps a base detector with custom name and description.
type wrappedDetector struct {
	detector    detectors.Detector
	name        string
	description string
}

func (w *wrappedDetector) Detect(ctx context.Context, a *attempt.Attempt) ([]float64, error) {
	return w.detector.Detect(ctx, a)
}

func (w *wrappedDetector) Name() string {
	return w.name
}

func (w *wrappedDetector) Description() string {
	return w.description
}

// NewEICAR creates a detector for the EICAR antivirus test signature.
// Detects: "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
func NewEICAR(_ registry.Config) (detectors.Detector, error) {
	baseDetector, err := base.NewStringDetector(registry.Config{
		"substrings": []string{EICARSignature},
	})
	if err != nil {
		return nil, err
	}

	return &wrappedDetector{
		detector:    baseDetector,
		name:        "knownbadsignatures.EICAR",
		description: "Detects EICAR antivirus test signature",
	}, nil
}

// NewGTUBE creates a detector for the GTUBE spam test signature.
// Detects: "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
func NewGTUBE(_ registry.Config) (detectors.Detector, error) {
	baseDetector, err := base.NewStringDetector(registry.Config{
		"substrings": []string{GTUBESignature},
	})
	if err != nil {
		return nil, err
	}

	return &wrappedDetector{
		detector:    baseDetector,
		name:        "knownbadsignatures.GTUBE",
		description: "Detects GTUBE spam test signature",
	}, nil
}

// NewGTphish creates a detector for the GTphish phishing test signature.
// Detects: "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTPHISH-STANDARD-ANTI-PHISH-TEST-EMAIL*C.34X"
func NewGTphish(_ registry.Config) (detectors.Detector, error) {
	baseDetector, err := base.NewStringDetector(registry.Config{
		"substrings": []string{GTphishSignature},
	})
	if err != nil {
		return nil, err
	}

	return &wrappedDetector{
		detector:    baseDetector,
		name:        "knownbadsignatures.GTphish",
		description: "Detects GTphish phishing test signature",
	}, nil
}
