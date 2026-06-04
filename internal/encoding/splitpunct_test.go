package encoding

import "testing"

func TestSplitTrailingPunctuation(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantBase string
		wantPunc string
	}{
		{
			name:     "no punctuation",
			input:    "hello",
			wantBase: "hello",
			wantPunc: "",
		},
		{
			name:     "single trailing punctuation",
			input:    "hello!",
			wantBase: "hello",
			wantPunc: "!",
		},
		{
			name:     "multiple trailing punctuation",
			input:    "world...",
			wantBase: "world",
			wantPunc: "...",
		},
		{
			name:     "question and exclamation",
			input:    "what?!",
			wantBase: "what",
			wantPunc: "?!",
		},
		{
			name:     "pure punctuation",
			input:    "!!!",
			wantBase: "",
			wantPunc: "!!!",
		},
		{
			name:     "empty string",
			input:    "",
			wantBase: "",
			wantPunc: "",
		},
		{
			name:     "numbers preserved",
			input:    "abc123",
			wantBase: "abc123",
			wantPunc: "",
		},
		{
			name:     "number with punctuation",
			input:    "123!",
			wantBase: "123",
			wantPunc: "!",
		},
		{
			name:     "multi-byte UTF-8 with punctuation",
			input:    "café!",
			wantBase: "café",
			wantPunc: "!",
		},
		{
			name:     "accented letters no punctuation",
			input:    "naïve",
			wantBase: "naïve",
			wantPunc: "",
		},
		{
			name:     "CJK characters with punctuation",
			input:    "你好！",
			wantBase: "你好",
			wantPunc: "！",
		},
		{
			name:     "decomposed accent with punctuation",
			input:    "cafe\u0301!",
			wantBase: "cafe\u0301",
			wantPunc: "!",
		},
		{
			name:     "decomposed accent no punctuation",
			input:    "cafe\u0301",
			wantBase: "cafe\u0301",
			wantPunc: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, punc := SplitTrailingPunctuation(tt.input)
			if base != tt.wantBase {
				t.Errorf("SplitTrailingPunctuation(%q) base = %q, want %q", tt.input, base, tt.wantBase)
			}
			if punc != tt.wantPunc {
				t.Errorf("SplitTrailingPunctuation(%q) punc = %q, want %q", tt.input, punc, tt.wantPunc)
			}
		})
	}
}
