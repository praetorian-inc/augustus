package probes

import (
	"testing"
)

func TestLoadLines(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    []string
		wantErr bool
	}{
		{
			name: "basic lines",
			data: []byte("line1\nline2\nline3\n"),
			want: []string{"line1", "line2", "line3"},
		},
		{
			name: "skips empty lines",
			data: []byte("line1\n\nline2\n\n\nline3\n"),
			want: []string{"line1", "line2", "line3"},
		},
		{
			name: "trims whitespace",
			data: []byte("  line1  \n\tline2\t\n  line3\n"),
			want: []string{"line1", "line2", "line3"},
		},
		{
			name: "empty input",
			data: []byte(""),
			want: nil,
		},
		{
			name: "only whitespace",
			data: []byte("  \n\t\n  \n"),
			want: nil,
		},
		{
			name: "no trailing newline",
			data: []byte("line1\nline2"),
			want: []string{"line1", "line2"},
		},
		{
			name: "preserves comment lines",
			data: []byte("# comment\nline1\n"),
			want: []string{"# comment", "line1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadLines(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadLines() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("LoadLines() returned %d lines, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("LoadLines()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestSplitLines(t *testing.T) {
	tests := []struct {
		name string
		data string
		want []string
	}{
		{
			name: "basic lines",
			data: "line1\nline2\nline3\n",
			want: []string{"line1", "line2", "line3"},
		},
		{
			name: "skips empty lines",
			data: "line1\n\nline2\n\n\nline3\n",
			want: []string{"line1", "line2", "line3"},
		},
		{
			name: "trims whitespace",
			data: "  line1  \n\tline2\t\n  line3\n",
			want: []string{"line1", "line2", "line3"},
		},
		{
			name: "empty input",
			data: "",
			want: []string{},
		},
		{
			name: "preserves comment lines",
			data: "# comment\nline1\n",
			want: []string{"# comment", "line1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitLines(tt.data)
			if len(got) != len(tt.want) {
				t.Errorf("SplitLines() returned %d lines, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("SplitLines()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestSplitLinesSkipComments(t *testing.T) {
	tests := []struct {
		name string
		data string
		want []string
	}{
		{
			name: "basic lines",
			data: "line1\nline2\nline3\n",
			want: []string{"line1", "line2", "line3"},
		},
		{
			name: "skips comments",
			data: "# comment\nline1\n# another comment\nline2\n",
			want: []string{"line1", "line2"},
		},
		{
			name: "skips indented comments",
			data: "  # comment\nline1\n",
			want: []string{"line1"},
		},
		{
			name: "skips empty lines",
			data: "line1\n\nline2\n",
			want: []string{"line1", "line2"},
		},
		{
			name: "empty input",
			data: "",
			want: []string{},
		},
		{
			name: "only comments",
			data: "# comment1\n# comment2\n",
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitLinesSkipComments(tt.data)
			if len(got) != len(tt.want) {
				t.Errorf("SplitLinesSkipComments() returned %d lines, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("SplitLinesSkipComments()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
