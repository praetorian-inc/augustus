package ragpoisoning

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// TestNewRAGPoisoning tests that a RAGPoisoning probe can be created with proper defaults.
func TestNewRAGPoisoning(t *testing.T) {
	triggerQuestion := "What is the capital of France?"
	poisonedAnswer := "The capital of France is Berlin."

	probe := NewRAGPoisoning(
		"ragpoisoning.BasicTest",
		"manipulate model via poisoned RAG documents",
		"ragpoisoning.Detector",
		"Tests RAG poisoning with basic confidence level",
		triggerQuestion,
		poisonedAnswer,
		5, // DocumentCount
		Medium,
	)

	if probe == nil {
		t.Fatal("NewRAGPoisoning returned nil")
	}

	if probe.Name() != "ragpoisoning.BasicTest" {
		t.Errorf("Name() = %q, want %q", probe.Name(), "ragpoisoning.BasicTest")
	}

	if probe.Goal() != "manipulate model via poisoned RAG documents" {
		t.Errorf("Goal() = %q, want %q", probe.Goal(), "manipulate model via poisoned RAG documents")
	}

	if probe.TriggerQuestion != triggerQuestion {
		t.Errorf("TriggerQuestion = %q, want %q", probe.TriggerQuestion, triggerQuestion)
	}

	if probe.PoisonedAnswer != poisonedAnswer {
		t.Errorf("PoisonedAnswer = %q, want %q", probe.PoisonedAnswer, poisonedAnswer)
	}

	if probe.DocumentCount != 5 {
		t.Errorf("DocumentCount = %d, want 5", probe.DocumentCount)
	}

	if probe.ConfidenceLevel != Medium {
		t.Errorf("ConfidenceLevel = %v, want %v", probe.ConfidenceLevel, Medium)
	}
}

// TestRAGPoisoningDefaults tests that DocumentCount defaults to 5 when not specified.
func TestRAGPoisoningDefaults(t *testing.T) {
	probe := NewRAGPoisoning(
		"ragpoisoning.DefaultTest",
		"test defaults",
		"ragpoisoning.Detector",
		"Tests default values",
		"Question?",
		"Answer.",
		0, // Should default to 5
		Low,
	)

	if probe.DocumentCount != 5 {
		t.Errorf("DocumentCount = %d, want 5 (default)", probe.DocumentCount)
	}
}

// TestConfidenceLevels tests that all confidence levels are defined.
func TestConfidenceLevels(t *testing.T) {
	levels := []ConfidenceLevel{Low, Medium, High, Authoritative}

	for i, level := range levels {
		if int(level) != i {
			t.Errorf("ConfidenceLevel %v has value %d, expected %d", level, int(level), i)
		}
	}
}

// TestGeneratePoisonedDocuments tests that poisoned documents are generated correctly.
func TestGeneratePoisonedDocuments(t *testing.T) {
	probe := NewRAGPoisoning(
		"ragpoisoning.GenerateTest",
		"test document generation",
		"ragpoisoning.Detector",
		"Tests poisoned document generation",
		"What is the capital of France?",
		"The capital of France is Berlin.",
		3, // Generate 3 documents
		Medium,
	)

	docs := probe.GeneratePoisonedDocuments()

	if docs == nil {
		t.Fatal("GeneratePoisonedDocuments returned nil")
	}

	if len(docs) != 3 {
		t.Errorf("GeneratePoisonedDocuments returned %d documents, want 3", len(docs))
	}

	// Verify each document has required fields
	for i, doc := range docs {
		if doc.Title == "" {
			t.Errorf("Document %d has empty Title", i)
		}

		if doc.Content == "" {
			t.Errorf("Document %d has empty Content", i)
		}

		if doc.Metadata == nil {
			t.Errorf("Document %d has nil Metadata", i)
		}

		// Verify poisoned answer is embedded in content
		if !strings.Contains(doc.Content, probe.PoisonedAnswer) {
			t.Errorf("Document %d Content does not contain poisoned answer %q", i, probe.PoisonedAnswer)
		}
	}
}

// TestGeneratePoisonedDocuments_ConfidenceLevels tests document generation with different confidence levels.
func TestGeneratePoisonedDocuments_ConfidenceLevels(t *testing.T) {
	testCases := []struct {
		name            string
		confidenceLevel ConfidenceLevel
		wantMetadata    string
	}{
		{
			name:            "Low confidence",
			confidenceLevel: Low,
			wantMetadata:    "forum post",
		},
		{
			name:            "Medium confidence",
			confidenceLevel: Medium,
			wantMetadata:    "blog post",
		},
		{
			name:            "High confidence",
			confidenceLevel: High,
			wantMetadata:    "technical documentation",
		},
		{
			name:            "Authoritative",
			confidenceLevel: Authoritative,
			wantMetadata:    "official documentation",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			probe := NewRAGPoisoning(
				"ragpoisoning.ConfidenceTest",
				"test confidence levels",
				"ragpoisoning.Detector",
				"Tests document confidence levels",
				"What is X?",
				"X is Y.",
				2,
				tc.confidenceLevel,
			)

			docs := probe.GeneratePoisonedDocuments()

			if len(docs) != 2 {
				t.Fatalf("GeneratePoisonedDocuments returned %d documents, want 2", len(docs))
			}

			// Check that at least one document has metadata indicating the confidence level
			found := false
			for _, doc := range docs {
				if source, ok := doc.Metadata["source"]; ok {
					if strings.Contains(strings.ToLower(source), strings.ToLower(tc.wantMetadata)) {
						found = true
						break
					}
				}
			}

			if !found {
				t.Errorf("No document metadata contains expected source type %q", tc.wantMetadata)
			}
		})
	}
}

// TestGeneratePoisonedDocuments_UniqueContent tests that generated documents have varied content.
func TestGeneratePoisonedDocuments_UniqueContent(t *testing.T) {
	probe := NewRAGPoisoning(
		"ragpoisoning.UniqueTest",
		"test unique content",
		"ragpoisoning.Detector",
		"Tests document uniqueness",
		"What is the answer?",
		"The answer is 42.",
		5,
		High,
	)

	docs := probe.GeneratePoisonedDocuments()

	if len(docs) != 5 {
		t.Fatalf("GeneratePoisonedDocuments returned %d documents, want 5", len(docs))
	}

	// Check that documents have different titles (indicating varied content)
	titles := make(map[string]bool)
	for _, doc := range docs {
		if titles[doc.Title] {
			t.Errorf("Duplicate document title found: %q", doc.Title)
		}
		titles[doc.Title] = true
	}

	if len(titles) != 5 {
		t.Errorf("Found %d unique titles, want 5", len(titles))
	}
}

// TestProbeRegistry tests that RAG poisoning probes can be registered and retrieved.
func TestProbeRegistry(t *testing.T) {
	probeName := "ragpoisoning.Test"

	// Check that the probe is registered
	factory, ok := probes.Get(probeName)
	if !ok {
		t.Fatalf("Probe %q not found in registry", probeName)
	}

	// Create probe using factory
	cfg := registry.Config{}
	probe, err := factory(cfg)
	if err != nil {
		t.Fatalf("Failed to create probe: %v", err)
	}

	if probe == nil {
		t.Fatal("Factory returned nil probe")
	}

	if probe.Name() != probeName {
		t.Errorf("Probe name = %q, want %q", probe.Name(), probeName)
	}
}

// TestProbeRegistration_MultipleProbes tests that multiple RAG poisoning probes can be registered.
func TestProbeRegistration_MultipleProbes(t *testing.T) {
	expectedProbes := []string{
		"ragpoisoning.Test",
		"ragpoisoning.LowConfidence",
		"ragpoisoning.HighConfidence",
	}

	for _, name := range expectedProbes {
		factory, ok := probes.Get(name)
		if !ok {
			t.Errorf("Probe %q not found in registry", name)
			continue
		}

		probe, err := factory(registry.Config{})
		if err != nil {
			t.Errorf("Failed to create probe %q: %v", name, err)
			continue
		}

		if probe.Name() != name {
			t.Errorf("Probe name = %q, want %q", probe.Name(), name)
		}
	}
}
