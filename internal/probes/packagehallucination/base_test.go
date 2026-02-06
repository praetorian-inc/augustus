package packagehallucination

import (
	"testing"
)

func TestGeneratePrompts(t *testing.T) {
	prompts := generatePrompts("Python3")

	// Should generate 10 stub prompts × 24 code tasks = 240 prompts
	expectedCount := len(stubPrompts) * len(codeTasks)
	if len(prompts) != expectedCount {
		t.Errorf("generatePrompts() returned %d prompts, want %d", len(prompts), expectedCount)
	}

	// Verify placeholders are replaced
	for _, prompt := range prompts {
		if indexString(prompt, "<language>") != -1 {
			t.Errorf("generatePrompts() prompt still contains <language> placeholder: %q", prompt)
		}
		if indexString(prompt, "<task>") != -1 {
			t.Errorf("generatePrompts() prompt still contains <task> placeholder: %q", prompt)
		}
	}

	// Verify language name is included
	foundPython := false
	for _, prompt := range prompts {
		if indexString(prompt, "Python3") != -1 {
			foundPython = true
			break
		}
	}
	if !foundPython {
		t.Error("generatePrompts() prompts don't contain the language name 'Python3'")
	}

	// Verify at least one real task appears
	foundRealTask := false
	for _, prompt := range prompts {
		if indexString(prompt, "Latex escape") != -1 {
			foundRealTask = true
			break
		}
	}
	if !foundRealTask {
		t.Error("generatePrompts() prompts don't contain any real code tasks")
	}

	// Verify at least one unreal task appears
	foundUnrealTask := false
	for _, prompt := range prompts {
		if indexString(prompt, "StrombergDB") != -1 {
			foundUnrealTask = true
			break
		}
	}
	if !foundUnrealTask {
		t.Error("generatePrompts() prompts don't contain any unreal code tasks")
	}
}

func TestCodeTasks(t *testing.T) {
	// Verify codeTasks combines real and unreal
	expectedCount := len(realCodeTasks) + len(unrealCodeTasks)
	if len(codeTasks) != expectedCount {
		t.Errorf("codeTasks has %d tasks, want %d", len(codeTasks), expectedCount)
	}

	// Verify at least one real task present
	foundReal := false
	for _, task := range codeTasks {
		if task == "Latex escape some text" {
			foundReal = true
			break
		}
	}
	if !foundReal {
		t.Error("codeTasks doesn't contain expected real task")
	}

	// Verify at least one unreal task present
	foundUnreal := false
	for _, task := range codeTasks {
		if task == "create a StrombergDB table" {
			foundUnreal = true
			break
		}
	}
	if !foundUnreal {
		t.Error("codeTasks doesn't contain expected unreal task")
	}
}

func TestReplaceAll(t *testing.T) {
	tests := []struct {
		name string
		s    string
		old  string
		new  string
		want string
	}{
		{
			name: "single occurrence",
			s:    "Hello <name>",
			old:  "<name>",
			new:  "World",
			want: "Hello World",
		},
		{
			name: "multiple occurrences",
			s:    "<x> and <x> and <x>",
			old:  "<x>",
			new:  "Y",
			want: "Y and Y and Y",
		},
		{
			name: "no occurrence",
			s:    "Hello World",
			old:  "<name>",
			new:  "Test",
			want: "Hello World",
		},
		{
			name: "empty string",
			s:    "",
			old:  "<x>",
			new:  "Y",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := replaceAll(tt.s, tt.old, tt.new)
			if got != tt.want {
				t.Errorf("replaceAll(%q, %q, %q) = %q, want %q", tt.s, tt.old, tt.new, got, tt.want)
			}
		})
	}
}

func TestIndexString(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		substr string
		want   int
	}{
		{
			name:   "found at beginning",
			s:      "hello world",
			substr: "hello",
			want:   0,
		},
		{
			name:   "found in middle",
			s:      "hello world",
			substr: "world",
			want:   6,
		},
		{
			name:   "not found",
			s:      "hello world",
			substr: "xyz",
			want:   -1,
		},
		{
			name:   "empty substring",
			s:      "hello",
			substr: "",
			want:   0,
		},
		{
			name:   "substring longer than string",
			s:      "hi",
			substr: "hello",
			want:   -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := indexString(tt.s, tt.substr)
			if got != tt.want {
				t.Errorf("indexString(%q, %q) = %d, want %d", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}
