package attempt

import (
	"time"
)

// Status represents the state of an attempt.
type Status string

const (
	// StatusPending indicates the attempt has not been processed.
	StatusPending Status = "pending"
	// StatusComplete indicates the attempt finished successfully.
	StatusComplete Status = "complete"
	// StatusError indicates the attempt failed with an error.
	StatusError Status = "error"
)

// Attempt represents a single probe execution against a generator.
//
// An Attempt captures the full lifecycle of testing an LLM:
// - The input prompt(s) sent to the model
// - The output(s) received from the model
// - Detection scores from various detectors
// - Metadata about the probe and generator used
type Attempt struct {
	// ID is a unique identifier for this attempt.
	ID string `json:"id"`

	// Probe identifies which probe generated this attempt.
	Probe string `json:"probe"`

	// Generator identifies which generator was tested.
	Generator string `json:"generator"`

	// Detector identifies the primary detector for scoring.
	Detector string `json:"detector"`

	// Prompt is the input prompt (single-turn).
	Prompt string `json:"prompt"`

	// Prompts contains multiple prompts (multi-turn or batch).
	Prompts []string `json:"prompts,omitempty"`

	// Outputs contains the model's responses.
	Outputs []string `json:"outputs"`

	// Conversations holds multi-turn dialogue history.
	Conversations []*Conversation `json:"conversations,omitempty"`

	// Scores contains detection scores (0.0 = safe, 1.0 = vulnerable).
	Scores []float64 `json:"scores,omitempty"`

	// DetectorResults maps detector names to their scores.
	// Matches Python's attempt.detector_results[detector_name] = scores pattern.
	DetectorResults map[string][]float64 `json:"detector_results,omitempty"`

	// Status indicates the current state of the attempt.
	Status Status `json:"status"`

	// Error contains any error message if status is error.
	Error string `json:"error,omitempty"`

	// Timestamp records when the attempt was created.
	Timestamp time.Time `json:"timestamp"`

	// Duration records how long the attempt took.
	Duration time.Duration `json:"duration,omitempty"`

	// Metadata holds arbitrary key-value data.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// New creates a new attempt with the given prompt.
func New(prompt string) *Attempt {
	return &Attempt{
		Prompt:          prompt,
		Prompts:         []string{prompt},
		Outputs:         make([]string, 0),
		Scores:          make([]float64, 0),
		DetectorResults: make(map[string][]float64),
		Status:          StatusPending,
		Timestamp:       time.Now(),
		Metadata:        make(map[string]any),
	}
}

// NewWithPrompts creates a new attempt with multiple prompts.
func NewWithPrompts(prompts []string) *Attempt {
	prompt := ""
	if len(prompts) > 0 {
		prompt = prompts[0]
	}

	return &Attempt{
		Prompt:          prompt,
		Prompts:         prompts,
		Outputs:         make([]string, 0),
		Scores:          make([]float64, 0),
		DetectorResults: make(map[string][]float64),
		Status:          StatusPending,
		Timestamp:       time.Now(),
		Metadata:        make(map[string]any),
	}
}

// AddOutput appends an output to the attempt.
func (a *Attempt) AddOutput(output string) {
	a.Outputs = append(a.Outputs, output)
}

// AddScore appends a detection score to the attempt.
func (a *Attempt) AddScore(score float64) {
	a.Scores = append(a.Scores, score)
}

// SetDetectorResults stores detection scores for a specific detector.
func (a *Attempt) SetDetectorResults(detectorName string, scores []float64) {
	if a.DetectorResults == nil {
		a.DetectorResults = make(map[string][]float64)
	}
	a.DetectorResults[detectorName] = scores
}

// SetError marks the attempt as failed with an error message.
func (a *Attempt) SetError(err error) {
	a.Status = StatusError
	if err != nil {
		a.Error = err.Error()
	}
}

// Complete marks the attempt as successfully completed.
func (a *Attempt) Complete() {
	a.Status = StatusComplete
}

// IsVulnerable returns true if any score exceeds the threshold.
// Default threshold is 0.5 if not specified.
func (a *Attempt) IsVulnerable(threshold ...float64) bool {
	thresh := 0.5
	if len(threshold) > 0 {
		thresh = threshold[0]
	}

	for _, score := range a.Scores {
		if score > thresh {
			return true
		}
	}
	return false
}

// MaxScore returns the highest detection score, or 0 if no scores.
func (a *Attempt) MaxScore() float64 {
	if len(a.Scores) == 0 {
		return 0
	}

	max := a.Scores[0]
	for _, score := range a.Scores[1:] {
		if score > max {
			max = score
		}
	}
	return max
}

// WithMetadata sets a metadata key-value pair and returns the attempt.
func (a *Attempt) WithMetadata(key string, value any) *Attempt {
	if a.Metadata == nil {
		a.Metadata = make(map[string]any)
	}
	a.Metadata[key] = value
	return a
}

// GetMetadata retrieves a metadata value by key.
func (a *Attempt) GetMetadata(key string) (any, bool) {
	v, ok := a.Metadata[key]
	return v, ok
}

// Copy creates a shallow copy of the attempt with independent slices and maps.
func (a *Attempt) Copy() *Attempt {
	copied := *a

	if a.Prompts != nil {
		copied.Prompts = make([]string, len(a.Prompts))
		copy(copied.Prompts, a.Prompts)
	}
	if a.Outputs != nil {
		copied.Outputs = make([]string, len(a.Outputs))
		copy(copied.Outputs, a.Outputs)
	}
	if a.Scores != nil {
		copied.Scores = make([]float64, len(a.Scores))
		copy(copied.Scores, a.Scores)
	}
	if a.DetectorResults != nil {
		copied.DetectorResults = make(map[string][]float64, len(a.DetectorResults))
		for k, v := range a.DetectorResults {
			copied.DetectorResults[k] = append([]float64{}, v...)
		}
	}
	if a.Metadata != nil {
		copied.Metadata = make(map[string]any, len(a.Metadata))
		for k, v := range a.Metadata {
			copied.Metadata[k] = v
		}
	}

	return &copied
}
