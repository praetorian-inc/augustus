package ggml

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGgml_RequiresModelPath(t *testing.T) {
	cfg := Config{
		GgmlMainPath: "/usr/local/bin/llama",
	}

	_, err := NewGgmlTyped(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "model")
}

func TestNewGgml_RequiresGgmlExecutable(t *testing.T) {
	cfg := Config{
		ModelPath: "/path/to/model.gguf",
	}

	_, err := NewGgmlTyped(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "executable")
}

func TestNewGgml_ValidatesGgufMagic(t *testing.T) {
	// Create a temporary invalid file
	tmpDir := t.TempDir()
	invalidFile := filepath.Join(tmpDir, "invalid.gguf")
	err := os.WriteFile(invalidFile, []byte("not a gguf file"), 0644)
	require.NoError(t, err)

	// Create a fake executable
	fakeExec := filepath.Join(tmpDir, "fake_llama")
	err = os.WriteFile(fakeExec, []byte("#!/bin/sh\necho test"), 0755)
	require.NoError(t, err)

	cfg := Config{
		ModelPath:    invalidFile,
		GgmlMainPath: fakeExec,
	}

	_, err = NewGgmlTyped(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GGUF format")
}

func TestNewGgml_ValidatesGgufMagicBytes(t *testing.T) {
	// Create a temporary valid GGUF file (with magic bytes)
	tmpDir := t.TempDir()
	validFile := filepath.Join(tmpDir, "valid.gguf")
	ggufMagic := []byte{0x47, 0x47, 0x55, 0x46} // "GGUF"
	err := os.WriteFile(validFile, ggufMagic, 0644)
	require.NoError(t, err)

	// Create a fake executable
	fakeExec := filepath.Join(tmpDir, "fake_llama")
	err = os.WriteFile(fakeExec, []byte("#!/bin/sh\necho test"), 0755)
	require.NoError(t, err)

	cfg := Config{
		ModelPath:    validFile,
		GgmlMainPath: fakeExec,
	}

	gen, err := NewGgmlTyped(cfg)
	require.NoError(t, err)
	assert.NotNil(t, gen)
}

func TestNewGgml_FromEnvironment(t *testing.T) {
	// Create temporary files
	tmpDir := t.TempDir()
	modelFile := filepath.Join(tmpDir, "model.gguf")
	ggufMagic := []byte{0x47, 0x47, 0x55, 0x46}
	err := os.WriteFile(modelFile, ggufMagic, 0644)
	require.NoError(t, err)

	execFile := filepath.Join(tmpDir, "llama")
	err = os.WriteFile(execFile, []byte("#!/bin/sh\necho test"), 0755)
	require.NoError(t, err)

	// Set environment variable
	os.Setenv("GGML_MAIN_PATH", execFile)
	defer os.Unsetenv("GGML_MAIN_PATH")

	cfg := Config{
		ModelPath: modelFile,
	}

	gen, err := NewGgmlTyped(cfg)
	require.NoError(t, err)
	assert.NotNil(t, gen)
}

func TestNewGgml_DefaultParameters(t *testing.T) {
	tmpDir := t.TempDir()
	modelFile := filepath.Join(tmpDir, "model.gguf")
	ggufMagic := []byte{0x47, 0x47, 0x55, 0x46}
	err := os.WriteFile(modelFile, ggufMagic, 0644)
	require.NoError(t, err)

	execFile := filepath.Join(tmpDir, "llama")
	err = os.WriteFile(execFile, []byte("#!/bin/sh\necho test"), 0755)
	require.NoError(t, err)

	cfg := Config{
		ModelPath:    modelFile,
		GgmlMainPath: execFile,
	}

	gen, err := NewGgmlTyped(cfg)
	require.NoError(t, err)

	// Verify defaults are set
	assert.Equal(t, float64(0.8), gen.temperature)
	assert.Equal(t, 40, gen.topK)
	assert.Equal(t, 0.95, gen.topP)
	assert.Equal(t, 1.1, gen.repeatPenalty)
}

func TestNewGgml_CustomParameters(t *testing.T) {
	tmpDir := t.TempDir()
	modelFile := filepath.Join(tmpDir, "model.gguf")
	ggufMagic := []byte{0x47, 0x47, 0x55, 0x46}
	err := os.WriteFile(modelFile, ggufMagic, 0644)
	require.NoError(t, err)

	execFile := filepath.Join(tmpDir, "llama")
	err = os.WriteFile(execFile, []byte("#!/bin/sh\necho test"), 0755)
	require.NoError(t, err)

	cfg := Config{
		ModelPath:    modelFile,
		GgmlMainPath: execFile,
		Temperature:  0.5,
		TopK:         50,
		TopP:         0.9,
		MaxTokens:    100,
	}

	gen, err := NewGgmlTyped(cfg)
	require.NoError(t, err)

	assert.Equal(t, 0.5, gen.temperature)
	assert.Equal(t, 50, gen.topK)
	assert.Equal(t, 0.9, gen.topP)
	assert.Equal(t, 100, gen.maxTokens)
}

func TestGgml_Name(t *testing.T) {
	tmpDir := t.TempDir()
	modelFile := filepath.Join(tmpDir, "model.gguf")
	ggufMagic := []byte{0x47, 0x47, 0x55, 0x46}
	err := os.WriteFile(modelFile, ggufMagic, 0644)
	require.NoError(t, err)

	execFile := filepath.Join(tmpDir, "llama")
	err = os.WriteFile(execFile, []byte("#!/bin/sh\necho test"), 0755)
	require.NoError(t, err)

	cfg := Config{
		ModelPath:    modelFile,
		GgmlMainPath: execFile,
	}

	gen, err := NewGgmlTyped(cfg)
	require.NoError(t, err)

	assert.Equal(t, "ggml.Ggml", gen.Name())
}

func TestGgml_Description(t *testing.T) {
	tmpDir := t.TempDir()
	modelFile := filepath.Join(tmpDir, "model.gguf")
	ggufMagic := []byte{0x47, 0x47, 0x55, 0x46}
	err := os.WriteFile(modelFile, ggufMagic, 0644)
	require.NoError(t, err)

	execFile := filepath.Join(tmpDir, "llama")
	err = os.WriteFile(execFile, []byte("#!/bin/sh\necho test"), 0755)
	require.NoError(t, err)

	cfg := Config{
		ModelPath:    modelFile,
		GgmlMainPath: execFile,
	}

	gen, err := NewGgmlTyped(cfg)
	require.NoError(t, err)

	desc := gen.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "ggml")
}

func TestGgml_ClearHistory(t *testing.T) {
	tmpDir := t.TempDir()
	modelFile := filepath.Join(tmpDir, "model.gguf")
	ggufMagic := []byte{0x47, 0x47, 0x55, 0x46}
	err := os.WriteFile(modelFile, ggufMagic, 0644)
	require.NoError(t, err)

	execFile := filepath.Join(tmpDir, "llama")
	err = os.WriteFile(execFile, []byte("#!/bin/sh\necho test"), 0755)
	require.NoError(t, err)

	cfg := Config{
		ModelPath:    modelFile,
		GgmlMainPath: execFile,
	}

	gen, err := NewGgmlTyped(cfg)
	require.NoError(t, err)

	// Should not panic
	gen.ClearHistory()
}

func TestGgml_Generate_NoTokens(t *testing.T) {
	tmpDir := t.TempDir()
	modelFile := filepath.Join(tmpDir, "model.gguf")
	ggufMagic := []byte{0x47, 0x47, 0x55, 0x46}
	err := os.WriteFile(modelFile, ggufMagic, 0644)
	require.NoError(t, err)

	execFile := filepath.Join(tmpDir, "llama")
	err = os.WriteFile(execFile, []byte("#!/bin/sh\necho test"), 0755)
	require.NoError(t, err)

	cfg := Config{
		ModelPath:    modelFile,
		GgmlMainPath: execFile,
	}

	gen, err := NewGgmlTyped(cfg)
	require.NoError(t, err)

	conv := &attempt.Conversation{
		Turns: []attempt.Turn{
			{Prompt: attempt.NewUserMessage("test")},
		},
	}

	responses, err := gen.Generate(context.Background(), conv, 0)
	require.NoError(t, err)
	assert.Empty(t, responses)
}
