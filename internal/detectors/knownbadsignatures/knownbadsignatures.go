// Package knownbadsignatures provides detectors for known malware/spam test signatures.
//
// These detectors identify test signatures designed to verify antivirus, spam,
// and phishing detection systems (EICAR, GTUBE, GTphish).
package knownbadsignatures

import (
	"github.com/praetorian-inc/augustus/internal/detectors/base"
	"github.com/praetorian-inc/augustus/pkg/detectors"
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

// NewEICAR creates a detector for the EICAR antivirus test signature.
// Detects: "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
func NewEICAR(_ registry.Config) (detectors.Detector, error) {
	return base.NewSubstringDetector("knownbadsignatures.EICAR", "Detects EICAR antivirus test signature",
		[]string{EICARSignature})
}

// NewGTUBE creates a detector for the GTUBE spam test signature.
// Detects: "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
func NewGTUBE(_ registry.Config) (detectors.Detector, error) {
	return base.NewSubstringDetector("knownbadsignatures.GTUBE", "Detects GTUBE spam test signature",
		[]string{GTUBESignature})
}

// NewGTphish creates a detector for the GTphish phishing test signature.
// Detects: "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTPHISH-STANDARD-ANTI-PHISH-TEST-EMAIL*C.34X"
func NewGTphish(_ registry.Config) (detectors.Detector, error) {
	return base.NewSubstringDetector("knownbadsignatures.GTphish", "Detects GTphish phishing test signature",
		[]string{GTphishSignature})
}
