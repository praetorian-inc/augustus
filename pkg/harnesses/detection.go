// Package harnesses provides shared logic for harness implementations.
package harnesses

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
)

// DetectorErrorBehavior defines how detector errors should be handled.
type DetectorErrorBehavior int

const (
	// SkipOnError logs warnings and continues to the next detector.
	// Used by harnesses that want to accumulate partial results.
	SkipOnError DetectorErrorBehavior = iota

	// FailOnError returns immediately on any detector error.
	// Used by harnesses that need strict error propagation.
	FailOnError
)

// ApplyDetectors runs all detectors on the given attempt and selects the primary detector.
//
// The function:
// 1. Runs each detector and stores results via SetDetectorResults
// 2. Tracks the detector with the highest score as primary
// 3. Falls back to the first detector if no scores are found
// 4. Marks the attempt as Complete (unless already in StatusError)
//
// Error handling is controlled by onError:
// - SkipOnError: logs warnings and continues to next detector
// - FailOnError: returns immediately on first detector error
func ApplyDetectors(
	ctx context.Context,
	a *attempt.Attempt,
	detectorList []detectors.Detector,
	onError DetectorErrorBehavior,
) error {
	maxScore := 0.0
	primaryDetector := ""
	var primaryScores []float64
	firstDetector := ""
	var firstScores []float64

	for _, detector := range detectorList {
		slog.Debug("running detector", "detector", detector.Name(), "probe", a.Probe)

		scores, err := detector.Detect(ctx, a)
		if err != nil {
			if onError == SkipOnError {
				slog.Warn("detector failed, skipping",
					"detector", detector.Name(),
					"probe", a.Probe,
					"error", err)
				continue
			}
			// FailOnError: return immediately
			return fmt.Errorf("detector %s failed: %w", detector.Name(), err)
		}

		// Store detector results
		a.SetDetectorResults(detector.Name(), scores)

		// Remember first detector as fallback
		if firstDetector == "" {
			firstDetector = detector.Name()
			firstScores = scores
		}

		// Track detector with highest score
		for _, score := range scores {
			if score > maxScore {
				maxScore = score
				primaryDetector = detector.Name()
				primaryScores = scores
			}
		}
	}

	// Set primary detector to one with highest score
	// If no detector had scores, use first detector
	if primaryDetector != "" {
		a.Detector = primaryDetector
		a.Scores = primaryScores
	} else if firstDetector != "" {
		a.Detector = firstDetector
		a.Scores = firstScores
	}

	// Mark attempt as complete only if not in error state
	if a.Status != attempt.StatusError {
		a.Complete()
	}

	return nil
}
