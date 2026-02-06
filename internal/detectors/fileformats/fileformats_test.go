package fileformats

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPossiblePickleName(t *testing.T) {
	detector, err := NewPossiblePickleName(nil)
	require.NoError(t, err)

	tests := []struct {
		name     string
		filename string
		expected float64
	}{
		{
			name:     "pkl_extension",
			filename: "model.pkl",
			expected: 1.0,
		},
		{
			name:     "pickle_extension",
			filename: "data.pickle",
			expected: 1.0,
		},
		{
			name:     "pkl_uppercase",
			filename: "MODEL.PKL",
			expected: 1.0,
		},
		{
			name:     "pickle_mixed_case",
			filename: "Data.PICKLE",
			expected: 1.0,
		},
		{
			name:     "safe_json",
			filename: "config.json",
			expected: 0.0,
		},
		{
			name:     "safe_txt",
			filename: "README.txt",
			expected: 0.0,
		},
		{
			name:     "pkl_in_name_but_different_ext",
			filename: "pickled_data.json",
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &attempt.Attempt{
				Outputs: []string{tt.filename},
			}

			scores, err := detector.Detect(context.Background(), a)
			require.NoError(t, err)
			require.Len(t, scores, 1)
			assert.Equal(t, tt.expected, scores[0], "unexpected score for: %s", tt.filename)
		})
	}
}

func TestFileIsExecutable(t *testing.T) {
	detector, err := NewFileIsExecutable(nil)
	require.NoError(t, err)

	// Create temp directory for test files
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		content  []byte
		expected float64
		skip     string // Skip reason if magic library not available
	}{
		{
			name:     "shell_script",
			content:  []byte("#!/bin/bash\necho 'test'\n"),
			expected: 1.0,
		},
		{
			name:     "text_file",
			content:  []byte("This is just plain text\n"),
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
			tmpFile := filepath.Join(tmpDir, tt.name)
			err := os.WriteFile(tmpFile, tt.content, 0644)
			require.NoError(t, err)

			a := &attempt.Attempt{
				Outputs: []string{tmpFile},
			}

			scores, err := detector.Detect(context.Background(), a)
			require.NoError(t, err)
			require.Len(t, scores, 1)

			// If magic library not available, expect nil score
			if scores[0] < 0 {
				t.Skip("magic library not available")
				return
			}

			assert.Equal(t, tt.expected, scores[0], "unexpected score for: %s", tt.name)
		})
	}
}

func TestPossiblePickleName_Name(t *testing.T) {
	detector, err := NewPossiblePickleName(nil)
	require.NoError(t, err)
	assert.Equal(t, "fileformats.PossiblePickleName", detector.Name())
}

func TestFileIsExecutable_Name(t *testing.T) {
	detector, err := NewFileIsExecutable(nil)
	require.NoError(t, err)
	assert.Equal(t, "fileformats.FileIsExecutable", detector.Name())
}
