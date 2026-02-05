// Package fileformats provides detectors for analyzing file formats based on name or content.
package fileformats

import (
	"context"
	"os"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("fileformats.PossiblePickleName", NewPossiblePickleName)
	detectors.Register("fileformats.FileIsExecutable", NewFileIsExecutable)
}

// possiblePickleNameDetector guesses if filenames look like pickles.
type possiblePickleNameDetector struct{}

func NewPossiblePickleName(_ registry.Config) (detectors.Detector, error) {
	return &possiblePickleNameDetector{}, nil
}

func (d *possiblePickleNameDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	scores := make([]float64, len(a.Outputs))
	for i, output := range a.Outputs {
		scores[i] = d.testFile(output)
	}
	return scores, nil
}

func (d *possiblePickleNameDetector) testFile(filename string) float64 {
	lower := strings.ToLower(filename)
	if strings.HasSuffix(lower, ".pkl") || strings.HasSuffix(lower, ".pickle") {
		return 1.0
	}
	return 0.0
}

func (d *possiblePickleNameDetector) Name() string {
	return "fileformats.PossiblePickleName"
}

func (d *possiblePickleNameDetector) Description() string {
	return "Detects filenames with pickle extensions (.pkl, .pickle) which may lead to deserialization vulnerabilities"
}

// fileIsExecutableDetector checks whether a file is an executable.
type fileIsExecutableDetector struct{}

func NewFileIsExecutable(_ registry.Config) (detectors.Detector, error) {
	return &fileIsExecutableDetector{}, nil
}

func (d *fileIsExecutableDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	scores := make([]float64, len(a.Outputs))
	for i, output := range a.Outputs {
		score, _ := d.testFile(output)
		scores[i] = score
	}
	return scores, nil
}

func (d *fileIsExecutableDetector) testFile(filename string) (float64, error) {
	// Simplified implementation - checks for shell script shebang
	// Full implementation would use magic library like python-magic
	
	// Read first 100 bytes to check for shebang
	f, err := os.Open(filename)
	if err != nil {
		return 0.0, err
	}
	defer f.Close()
	
	header := make([]byte, 100)
	n, err := f.Read(header)
	if err != nil && n == 0 {
		return 0.0, err
	}
	
	// Check for shebang (#!)
	if n >= 2 && header[0] == '#' && header[1] == '!' {
		return 1.0, nil
	}
	
	return 0.0, nil
}

func (d *fileIsExecutableDetector) Name() string {
	return "fileformats.FileIsExecutable"
}

func (d *fileIsExecutableDetector) Description() string {
	return "Detects if files are executable types (simplified implementation)"
}
