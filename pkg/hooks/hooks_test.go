package hooks

import (
	"context"
	"testing"
	"time"
)

func TestParseKeyValueLines(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]string
	}{
		{
			name:  "simple key-value pairs",
			input: "FOO=bar\nBAZ=qux\n",
			expected: map[string]string{
				"FOO": "bar",
				"BAZ": "qux",
			},
		},
		{
			name:  "keys are uppercased",
			input: "conversation_id=abc123\nparent_message_id=def456\n",
			expected: map[string]string{
				"CONVERSATION_ID":   "abc123",
				"PARENT_MESSAGE_ID": "def456",
			},
		},
		{
			name:     "comments and blank lines ignored",
			input:    "# this is a comment\n\nFOO=bar\n  # another comment\n",
			expected: map[string]string{"FOO": "bar"},
		},
		{
			name:     "lines without equals ignored",
			input:    "no equals here\nFOO=bar\njust text\n",
			expected: map[string]string{"FOO": "bar"},
		},
		{
			name:  "value with equals sign",
			input: "TOKEN=abc=def=ghi\n",
			expected: map[string]string{
				"TOKEN": "abc=def=ghi",
			},
		},
		{
			name:     "empty input",
			input:    "",
			expected: map[string]string{},
		},
		{
			name:  "whitespace trimmed",
			input: "  FOO  =  bar  \n",
			expected: map[string]string{
				"FOO": "bar",
			},
		},
		{
			name:     "equals at start of line ignored",
			input:    "=value\nFOO=bar\n",
			expected: map[string]string{"FOO": "bar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseKeyValueLines(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("got %d vars, want %d", len(result), len(tt.expected))
			}
			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("key %q: got %q, want %q", k, result[k], v)
				}
			}
		})
	}
}

func TestParseKeyValueLines_InvalidKeysRejected(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]string
	}{
		{
			name:  "key with dash is skipped",
			input: "FOO-BAR=val\nVALID_KEY=ok\n",
			expected: map[string]string{
				"VALID_KEY": "ok",
			},
		},
		{
			name:  "key with dot is skipped",
			input: "has.dot=no\nGOOD=yes\n",
			expected: map[string]string{
				"GOOD": "yes",
			},
		},
		{
			name:  "key with space is skipped",
			input: "HAS SPACE=bad\nNO_SPACE=good\n",
			expected: map[string]string{
				"NO_SPACE": "good",
			},
		},
		{
			name:  "mixed valid and invalid keys",
			input: "FOO-BAR=val\nVALID_KEY=ok\nhas.dot=no\nANOTHER_GOOD=yes\nwith space=bad\n",
			expected: map[string]string{
				"VALID_KEY":    "ok",
				"ANOTHER_GOOD": "yes",
			},
		},
		{
			name:  "all invalid keys yields empty map",
			input: "a-b=1\nc.d=2\ne f=3\n",
			expected: map[string]string{},
		},
		{
			name:  "key with slash is skipped",
			input: "PATH/TO=val\nOK_KEY=fine\n",
			expected: map[string]string{
				"OK_KEY": "fine",
			},
		},
		{
			name:  "numeric keys are valid",
			input: "KEY123=val\n456=num\n",
			expected: map[string]string{
				"KEY123": "val",
				"456":    "num",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseKeyValueLines(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("got %d vars, want %d: %v", len(result), len(tt.expected), result)
			}
			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("key %q: got %q, want %q", k, result[k], v)
				}
			}
		})
	}
}

func TestHookRun(t *testing.T) {
	ctx := context.Background()

	t.Run("empty command returns empty result", func(t *testing.T) {
		h := &Hook{Command: ""}
		result, err := h.Run(ctx, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Variables) != 0 {
			t.Errorf("expected empty variables, got %v", result.Variables)
		}
	})

	t.Run("echo key-value pairs", func(t *testing.T) {
		h := &Hook{Command: `echo "CONVERSATION_ID=abc123"; echo "MESSAGE_ID=def456"`}
		result, err := h.Run(ctx, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Variables["CONVERSATION_ID"] != "abc123" {
			t.Errorf("CONVERSATION_ID: got %q, want %q", result.Variables["CONVERSATION_ID"], "abc123")
		}
		if result.Variables["MESSAGE_ID"] != "def456" {
			t.Errorf("MESSAGE_ID: got %q, want %q", result.Variables["MESSAGE_ID"], "def456")
		}
	})

	t.Run("receives environment variables", func(t *testing.T) {
		h := &Hook{Command: `echo "RESULT=$AUGUSTUS_TEST_VAR"`}
		env := map[string]string{"AUGUSTUS_TEST_VAR": "hello"}
		result, err := h.Run(ctx, env)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Variables["RESULT"] != "hello" {
			t.Errorf("RESULT: got %q, want %q", result.Variables["RESULT"], "hello")
		}
	})

	t.Run("failing command returns error", func(t *testing.T) {
		h := &Hook{Command: "exit 1"}
		_, err := h.Run(ctx, nil)
		if err == nil {
			t.Fatal("expected error for failing command")
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		h := &Hook{Command: "sleep 10"}
		_, err := h.Run(ctx, nil)
		if err == nil {
			t.Fatal("expected error for cancelled context")
		}
	})

	t.Run("captures stderr", func(t *testing.T) {
		h := &Hook{Command: `echo "FOO=bar"; echo "debug info" >&2`}
		result, err := h.Run(ctx, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Variables["FOO"] != "bar" {
			t.Errorf("FOO: got %q, want %q", result.Variables["FOO"], "bar")
		}
		if result.Stderr == "" {
			t.Error("expected stderr to be captured")
		}
	})

	t.Run("mixed output with non-KV lines", func(t *testing.T) {
		h := &Hook{Command: `echo "Starting setup..."; echo "ID=12345"; echo "Setup complete"`}
		result, err := h.Run(ctx, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Variables) != 1 {
			t.Errorf("expected 1 variable, got %d: %v", len(result.Variables), result.Variables)
		}
		if result.Variables["ID"] != "12345" {
			t.Errorf("ID: got %q, want %q", result.Variables["ID"], "12345")
		}
	})
}

func TestContextVars(t *testing.T) {
	t.Run("round-trip through context", func(t *testing.T) {
		vars := map[string]string{"FOO": "bar", "BAZ": "qux"}
		ctx := WithVars(context.Background(), vars)
		got := VarsFromContext(ctx)
		if got == nil {
			t.Fatal("expected vars from context, got nil")
		}
		if got["FOO"] != "bar" || got["BAZ"] != "qux" {
			t.Errorf("got %v, want %v", got, vars)
		}
	})

	t.Run("nil context returns nil", func(t *testing.T) {
		got := VarsFromContext(context.Background())
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
}
