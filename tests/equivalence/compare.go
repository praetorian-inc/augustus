package equivalence

import (
	"fmt"
	"math"
)

// FloatEpsilon is the tolerance for floating point comparison.
const FloatEpsilon = 1e-9

// CompareGeneratorOutputs compares generator results from Go and Python.
func CompareGeneratorOutputs(goResult, pyResult *GeneratorResult) ComparisonResult {
	result := ComparisonResult{
		Equivalent:  true,
		Differences: make([]Difference, 0),
	}

	// Compare success status
	if goResult.Success != pyResult.Success {
		result.Equivalent = false
		result.Differences = append(result.Differences, Difference{
			Field:   "success",
			GoValue: goResult.Success,
			PyValue: pyResult.Success,
			Message: fmt.Sprintf("Success status differs: Go=%v, Python=%v", goResult.Success, pyResult.Success),
		})
	}

	// If either failed, compare error messages
	if !goResult.Success || !pyResult.Success {
		if goResult.Error != pyResult.Error {
			result.Equivalent = false
			result.Differences = append(result.Differences, Difference{
				Field:   "error",
				GoValue: goResult.Error,
				PyValue: pyResult.Error,
				Message: "Error messages differ",
			})
		}
		return result
	}

	// Both succeeded - compare outputs
	if len(goResult.Outputs) != len(pyResult.Outputs) {
		result.Equivalent = false
		result.Differences = append(result.Differences, Difference{
			Field:   "outputs.length",
			GoValue: len(goResult.Outputs),
			PyValue: len(pyResult.Outputs),
			Message: fmt.Sprintf("Output count differs: Go=%d, Python=%d", len(goResult.Outputs), len(pyResult.Outputs)),
		})
		return result
	}

	// Compare each output string
	for i := range goResult.Outputs {
		if goResult.Outputs[i] != pyResult.Outputs[i] {
			result.Equivalent = false
			result.Differences = append(result.Differences, Difference{
				Field:   fmt.Sprintf("outputs[%d]", i),
				GoValue: goResult.Outputs[i],
				PyValue: pyResult.Outputs[i],
				Message: fmt.Sprintf("Output %d differs", i),
			})
		}
	}

	return result
}

// CompareDetectorScores compares detector results from Go and Python.
func CompareDetectorScores(goResult, pyResult *DetectorResult) ComparisonResult {
	result := ComparisonResult{
		Equivalent:  true,
		Differences: make([]Difference, 0),
	}

	// Compare success status
	if goResult.Success != pyResult.Success {
		result.Equivalent = false
		result.Differences = append(result.Differences, Difference{
			Field:   "success",
			GoValue: goResult.Success,
			PyValue: pyResult.Success,
			Message: fmt.Sprintf("Success status differs: Go=%v, Python=%v", goResult.Success, pyResult.Success),
		})
	}

	// If either failed, compare error messages
	if !goResult.Success || !pyResult.Success {
		if goResult.Error != pyResult.Error {
			result.Equivalent = false
			result.Differences = append(result.Differences, Difference{
				Field:   "error",
				GoValue: goResult.Error,
				PyValue: pyResult.Error,
				Message: "Error messages differ",
			})
		}
		return result
	}

	// Both succeeded - compare scores
	if len(goResult.Scores) != len(pyResult.Scores) {
		result.Equivalent = false
		result.Differences = append(result.Differences, Difference{
			Field:   "scores.length",
			GoValue: len(goResult.Scores),
			PyValue: len(pyResult.Scores),
			Message: fmt.Sprintf("Score count differs: Go=%d, Python=%d", len(goResult.Scores), len(pyResult.Scores)),
		})
		return result
	}

	// Compare each score with epsilon tolerance
	for i := range goResult.Scores {
		if !floatsEqual(goResult.Scores[i], pyResult.Scores[i], FloatEpsilon) {
			result.Equivalent = false
			result.Differences = append(result.Differences, Difference{
				Field:   fmt.Sprintf("scores[%d]", i),
				GoValue: goResult.Scores[i],
				PyValue: pyResult.Scores[i],
				Message: fmt.Sprintf("Score %d differs (Go=%.9f, Python=%.9f, diff=%.9e)",
					i, goResult.Scores[i], pyResult.Scores[i],
					math.Abs(goResult.Scores[i]-pyResult.Scores[i])),
			})
		}
	}

	return result
}

// CompareProbePrompts compares probe results from Go and Python.
func CompareProbePrompts(goResult, pyResult *ProbeResult) ComparisonResult {
	result := ComparisonResult{
		Equivalent:  true,
		Differences: make([]Difference, 0),
	}

	// Compare success status
	if goResult.Success != pyResult.Success {
		result.Equivalent = false
		result.Differences = append(result.Differences, Difference{
			Field:   "success",
			GoValue: goResult.Success,
			PyValue: pyResult.Success,
			Message: fmt.Sprintf("Success status differs: Go=%v, Python=%v", goResult.Success, pyResult.Success),
		})
	}

	// If either failed, compare error messages
	if !goResult.Success || !pyResult.Success {
		if goResult.Error != pyResult.Error {
			result.Equivalent = false
			result.Differences = append(result.Differences, Difference{
				Field:   "error",
				GoValue: goResult.Error,
				PyValue: pyResult.Error,
				Message: "Error messages differ",
			})
		}
		return result
	}

	// Both succeeded - compare prompts
	if len(goResult.Prompts) != len(pyResult.Prompts) {
		result.Equivalent = false
		result.Differences = append(result.Differences, Difference{
			Field:   "prompts.length",
			GoValue: len(goResult.Prompts),
			PyValue: len(pyResult.Prompts),
			Message: fmt.Sprintf("Prompt count differs: Go=%d, Python=%d", len(goResult.Prompts), len(pyResult.Prompts)),
		})
		return result
	}

	// Compare each prompt (order matters for probes)
	for i := range goResult.Prompts {
		if goResult.Prompts[i] != pyResult.Prompts[i] {
			result.Equivalent = false
			result.Differences = append(result.Differences, Difference{
				Field:   fmt.Sprintf("prompts[%d]", i),
				GoValue: goResult.Prompts[i],
				PyValue: pyResult.Prompts[i],
				Message: fmt.Sprintf("Prompt %d differs", i),
			})
		}
	}

	// Compare primary detector
	if goResult.PrimaryDetector != pyResult.PrimaryDetector {
		result.Equivalent = false
		result.Differences = append(result.Differences, Difference{
			Field:   "primary_detector",
			GoValue: goResult.PrimaryDetector,
			PyValue: pyResult.PrimaryDetector,
			Message: fmt.Sprintf("Primary detector differs: Go=%s, Python=%s",
				goResult.PrimaryDetector, pyResult.PrimaryDetector),
		})
	}

	// Compare goal (optional field)
	if goResult.Goal != pyResult.Goal {
		// Goal might be empty in one or both, which is acceptable
		// Only mark as difference if both have values and they differ
		if goResult.Goal != "" && pyResult.Goal != "" {
			result.Equivalent = false
			result.Differences = append(result.Differences, Difference{
				Field:   "goal",
				GoValue: goResult.Goal,
				PyValue: pyResult.Goal,
				Message: fmt.Sprintf("Goal differs: Go=%q, Python=%q", goResult.Goal, pyResult.Goal),
			})
		}
	}

	return result
}

// floatsEqual compares two floats with epsilon tolerance.
func floatsEqual(a, b, epsilon float64) bool {
	return math.Abs(a-b) < epsilon
}
