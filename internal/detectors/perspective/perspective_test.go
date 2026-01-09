package perspective

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// TestPerspectiveDetector_BasicDetection tests basic toxicity detection
func TestPerspectiveDetector_BasicDetection(t *testing.T) {
	tests := []struct {
		name         string
		output       string
		toxicity     float64
		wantScore    float64
		threshold    float64
	}{
		{
			name:      "high toxicity exceeds threshold",
			output:    "You are a terrible person",
			toxicity:  0.9,
			wantScore: 0.9,
			threshold: 0.5,
		},
		{
			name:      "low toxicity below threshold",
			output:    "Have a nice day",
			toxicity:  0.1,
			wantScore: 0.1,
			threshold: 0.5,
		},
		{
			name:      "zero toxicity",
			output:    "Hello, how are you?",
			toxicity:  0.0,
			wantScore: 0.0,
			threshold: 0.5,
		},
		{
			name:      "maximum toxicity",
			output:    "Extremely offensive content",
			toxicity:  1.0,
			wantScore: 1.0,
			threshold: 0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock Perspective API server
			server := mockPerspectiveServer(t, map[string]float64{
				"TOXICITY": tt.toxicity,
			})
			defer server.Close()

			// Create detector with mock API endpoint
			d, err := NewPerspective(registry.Config{
				"api_key":   "test-api-key",
				"threshold": tt.threshold,
				"api_url":   server.URL,
			})
			if err != nil {
				t.Fatalf("NewPerspective() error = %v", err)
			}

			a := attempt.New("test prompt")
			a.AddOutput(tt.output)

			scores, err := d.Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}

			if len(scores) != 1 {
				t.Fatalf("Detect() returned %d scores, want 1", len(scores))
			}

			if scores[0] != tt.wantScore {
				t.Errorf("Detect() = %f, want %f", scores[0], tt.wantScore)
			}
		})
	}
}

// TestPerspectiveDetector_MultipleAttributes tests detection with multiple attribute types
func TestPerspectiveDetector_MultipleAttributes(t *testing.T) {
	server := mockPerspectiveServer(t, map[string]float64{
		"TOXICITY":        0.8,
		"SEVERE_TOXICITY": 0.6,
		"INSULT":          0.7,
	})
	defer server.Close()

	d, err := NewPerspective(registry.Config{
		"api_key":   "test-api-key",
		"threshold": 0.5,
		"attrs":     []any{"TOXICITY", "SEVERE_TOXICITY", "INSULT"},
		"api_url":   server.URL,
	})
	if err != nil {
		t.Fatalf("NewPerspective() error = %v", err)
	}

	a := attempt.New("test prompt")
	a.AddOutput("offensive content")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if len(scores) != 1 {
		t.Fatalf("Detect() returned %d scores, want 1", len(scores))
	}

	// Should use the maximum score across all attributes
	if scores[0] != 0.8 {
		t.Errorf("Detect() = %f, want 0.8 (max of all attributes)", scores[0])
	}
}

// TestPerspectiveDetector_MultipleOutputs tests detection with multiple outputs
func TestPerspectiveDetector_MultipleOutputs(t *testing.T) {
	callCount := 0
	toxicityScores := []float64{0.9, 0.2, 0.5}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if callCount >= len(toxicityScores) {
			t.Fatalf("Unexpected API call %d", callCount)
			return
		}

		response := perspectiveResponse{
			AttributeScores: map[string]attributeScore{
				"TOXICITY": {
					SummaryScore: scoreValue{Value: toxicityScores[callCount]},
				},
			},
		}

		callCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	d, err := NewPerspective(registry.Config{
		"api_key":   "test-api-key",
		"threshold": 0.5,
		"api_url":   server.URL,
	})
	if err != nil {
		t.Fatalf("NewPerspective() error = %v", err)
	}

	a := attempt.New("test prompt")
	a.AddOutput("You are terrible")     // High toxicity
	a.AddOutput("Have a nice day")      // Low toxicity
	a.AddOutput("This is borderline")   // Medium toxicity

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if len(scores) != 3 {
		t.Fatalf("Detect() returned %d scores, want 3", len(scores))
	}

	want := []float64{0.9, 0.2, 0.5}
	for i, wantScore := range want {
		if scores[i] != wantScore {
			t.Errorf("Detect() scores[%d] = %f, want %f", i, scores[i], wantScore)
		}
	}
}

// TestPerspectiveDetector_Name tests the Name method
func TestPerspectiveDetector_Name(t *testing.T) {
	d, err := NewPerspective(registry.Config{
		"api_key": "test-api-key",
	})
	if err != nil {
		t.Fatalf("NewPerspective() error = %v", err)
	}

	if got := d.Name(); got != "perspective.Perspective" {
		t.Errorf("Name() = %q, want %q", got, "perspective.Perspective")
	}
}

// TestPerspectiveDetector_Description tests the Description method
func TestPerspectiveDetector_Description(t *testing.T) {
	d, err := NewPerspective(registry.Config{
		"api_key": "test-api-key",
	})
	if err != nil {
		t.Fatalf("NewPerspective() error = %v", err)
	}

	desc := d.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
}

// TestPerspectiveDetector_Registration tests detector registration
func TestPerspectiveDetector_Registration(t *testing.T) {
	factory, ok := detectors.Get("perspective.Perspective")
	if !ok {
		t.Fatal("perspective.Perspective not registered")
	}

	d, err := factory(registry.Config{
		"api_key": "test-api-key",
	})
	if err != nil {
		t.Fatalf("factory() error = %v", err)
	}

	if d.Name() != "perspective.Perspective" {
		t.Errorf("factory created detector with name %q, want %q", d.Name(), "perspective.Perspective")
	}
}

// TestPerspectiveDetector_MissingAPIKey tests error handling for missing API key
func TestPerspectiveDetector_MissingAPIKey(t *testing.T) {
	_, err := NewPerspective(registry.Config{})
	if err == nil {
		t.Error("NewPerspective() with missing API key should return error")
	}
}

// TestPerspectiveDetector_ConfigurableThreshold tests threshold configuration
func TestPerspectiveDetector_ConfigurableThreshold(t *testing.T) {
	server := mockPerspectiveServer(t, map[string]float64{
		"TOXICITY": 0.6,
	})
	defer server.Close()

	// Test with custom threshold
	d, err := NewPerspective(registry.Config{
		"api_key":   "test-api-key",
		"threshold": 0.7,
		"api_url":   server.URL,
	})
	if err != nil {
		t.Fatalf("NewPerspective() error = %v", err)
	}

	a := attempt.New("test prompt")
	a.AddOutput("moderately toxic content")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if len(scores) != 1 {
		t.Fatalf("Detect() returned %d scores, want 1", len(scores))
	}

	// Score should be the actual toxicity value, not thresholded
	if scores[0] != 0.6 {
		t.Errorf("Detect() = %f, want 0.6", scores[0])
	}
}

// TestPerspectiveDetector_APIError tests error handling for API failures
func TestPerspectiveDetector_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	d, err := NewPerspective(registry.Config{
		"api_key": "test-api-key",
		"api_url": server.URL,
	})
	if err != nil {
		t.Fatalf("NewPerspective() error = %v", err)
	}

	a := attempt.New("test prompt")
	a.AddOutput("test output")

	_, err = d.Detect(context.Background(), a)
	if err == nil {
		t.Error("Detect() should return error when API fails")
	}
}

// mockPerspectiveServer creates a mock HTTP server that returns specified toxicity scores
func mockPerspectiveServer(t *testing.T, scores map[string]float64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and content type
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST request, got %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		attributeScores := make(map[string]attributeScore)
		for attr, score := range scores {
			attributeScores[attr] = attributeScore{
				SummaryScore: scoreValue{Value: score},
			}
		}

		response := perspectiveResponse{
			AttributeScores: attributeScores,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatalf("Failed to encode mock response: %v", err)
		}
	}))
}
