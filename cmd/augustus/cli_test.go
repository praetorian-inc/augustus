package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type kongExit struct{ code int }

// TestCLIStructParsing tests Kong CLI struct parses basic commands
func TestCLIStructParsing(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "help flag",
			args:        []string{"--help"},
			expectError: false,
		},
		{
			name:        "version command",
			args:        []string{"version"},
			expectError: false,
		},
		{
			name:        "list command",
			args:        []string{"list"},
			expectError: false,
		},
		{
			name:        "no command (defaults to help)",
			args:        []string{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cli struct {
				Debug   bool       `help:"Enable debug mode." short:"d"`
				Version VersionCmd `cmd:"" help:"Print version."`
				Help    HelpCmd    `cmd:"" hidden:"" default:"1"`
				List    ListCmd    `cmd:"" help:"List capabilities."`
				Scan    ScanCmd    `cmd:"" help:"Run scan."`
			}

			var stdout bytes.Buffer
			didExit := false
			exitCode := -1

			parser, err := kong.New(&cli,
				kong.Name("augustus"),
				kong.Exit(func(code int) { // Prevent os.Exit during tests
					didExit = true
					exitCode = code
					panic(kongExit{code: code})
				}),
			)
			require.NoError(t, err)
			parser.Stdout = &stdout
			parser.Stderr = &stdout

			var parseErr error
			func() {
				defer func() {
					if r := recover(); r != nil {
						if _, ok := r.(kongExit); ok {
							return
						}
						panic(r)
					}
				}()
				_, parseErr = parser.Parse(tt.args)
			}()

			if tt.expectError {
				assert.Error(t, parseErr)
				if tt.errorMsg != "" {
					assert.Contains(t, parseErr.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, parseErr)
			}

			// Help flag should render usage and exit 0.
			if tt.name == "help flag" {
				assert.True(t, didExit)
				assert.Equal(t, 0, exitCode)
				assert.Contains(t, stdout.String(), "Usage: augustus")
			} else {
				assert.False(t, didExit)
			}
		})
	}
}

// TestScanCmdRequiresGenerator tests that generator argument is required
func TestScanCmdRequiresGenerator(t *testing.T) {
	var cli struct {
		Scan ScanCmd `cmd:"" help:"Run scan."`
	}

	parser, err := kong.New(&cli,
		kong.Name("augustus"),
		kong.Exit(func(int) {}),
	)
	require.NoError(t, err)

	// Missing generator should fail
	_, err = parser.Parse([]string{"scan"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "generator")
}

// TestScanCmdMutuallyExclusiveFlags tests probe selection validation
func TestScanCmdMutuallyExclusiveFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		errorMsg    string
	}{
		{
			name: "single --probe flag is valid",
			args: []string{"scan", "openai.OpenAI", "--probe", "test.Blank"},
			expectError: false,
		},
		{
			name: "multiple --probe flags are valid",
			args: []string{"scan", "openai.OpenAI", "--probe", "test.Blank", "--probe", "dan.Dan1"},
			expectError: false,
		},
		{
			name: "--all flag alone is valid",
			args: []string{"scan", "openai.OpenAI", "--all"},
			expectError: false,
		},
		{
			name: "--probes-glob flag alone is valid",
			args: []string{"scan", "openai.OpenAI", "--probes-glob", "dan.*"},
			expectError: false,
		},
		{
			name: "--probe with --probes-glob should fail validation",
			args: []string{"scan", "openai.OpenAI", "--probe", "test.Blank", "--probes-glob", "dan.*"},
			expectError: true,
			errorMsg: "cannot use --probe with --probes-glob",
		},
		{
			name: "--probe with --all should fail validation",
			args: []string{"scan", "openai.OpenAI", "--probe", "test.Blank", "--all"},
			expectError: true,
			errorMsg: "cannot use --probe with",
		},
		{
			name: "--probes-glob with --all should fail (Kong xor)",
			args: []string{"scan", "openai.OpenAI", "--probes-glob", "dan.*", "--all"},
			expectError: true, // Kong's xor tag should catch this
		},
		{
			name: "missing probe selection should fail validation",
			args: []string{"scan", "openai.OpenAI"},
			expectError: true,
			errorMsg: "at least one --probe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cli struct {
				Scan ScanCmd `cmd:""`
			}

			parser, err := kong.New(&cli,
				kong.Name("augustus"),
				kong.Exit(func(int) {}),
			)
			require.NoError(t, err)

			ctx, err := parser.Parse(tt.args)

			// Check Kong parsing errors first
			if err != nil {
				if tt.expectError {
					if tt.errorMsg != "" {
						assert.Contains(t, err.Error(), tt.errorMsg)
					}
					return
				}
				t.Fatalf("unexpected parse error: %v", err)
			}

			// Run custom Validate() method
			if strings.HasPrefix(ctx.Command(), "scan") {
				err = cli.Scan.Validate()
				if tt.expectError {
					assert.Error(t, err)
					if tt.errorMsg != "" {
						assert.Contains(t, err.Error(), tt.errorMsg)
					}
				} else {
					assert.NoError(t, err)
				}
			}
		})
	}
}

// TestScanCmdConfigFileValidation tests config file vs JSON validation
func TestScanCmdConfigFileValidation(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		errorMsg    string
	}{
		{
			name: "config-file alone is valid",
			args: []string{"scan", "openai.OpenAI", "--probe", "test.Blank", "--config-file", "config.yaml"},
			expectError: false,
		},
		{
			name: "config JSON alone is valid",
			args: []string{"scan", "openai.OpenAI", "--probe", "test.Blank", "--config", `{"model":"gpt-4"}`},
			expectError: false,
		},
		{
			name: "both config-file and config should fail",
			args: []string{"scan", "openai.OpenAI", "--probe", "test.Blank", "--config-file", "config.yaml", "--config", `{"model":"gpt-4"}`},
			expectError: true,
			errorMsg: "cannot use both --config-file and --config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cli struct {
				Scan ScanCmd `cmd:""`
			}

			parser, err := kong.New(&cli,
				kong.Name("augustus"),
				kong.Exit(func(int) {}),
			)
			require.NoError(t, err)

			// Create a temp config file for tests that use --config-file.
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")
			require.NoError(t, os.WriteFile(configPath, []byte("generators: {}\n"), 0644))

			args := append([]string(nil), tt.args...)
			for i := range args {
				if args[i] == "config.yaml" {
					args[i] = configPath
				}
			}

			_, err = parser.Parse(args)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" && err != nil {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestScanCmdFlagParsing tests all scan flags are parsed correctly
func TestScanCmdFlagParsing(t *testing.T) {
	var cli struct {
		Scan ScanCmd `cmd:""`
	}

	parser, err := kong.New(&cli,
		kong.Name("augustus"),
		kong.Exit(func(int) {}),
	)
	require.NoError(t, err)

	args := []string{
		"scan",
		"openai.OpenAI",
		"--probe", "test.Blank",
		"--probe", "dan.Dan1",
		"--detector", "always.Always",
		"--detectors-glob", "always.*",
		"--config", `{"model":"gpt-4"}`,
		"--harness", "custom.Harness",
		"--timeout", "1h",
		"--format", "json",
		"--output", "results.jsonl",
		"--html", "report.html",
		"--verbose",
	}

	ctx, err := parser.Parse(args)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(ctx.Command(), "scan"))

	// Verify all fields parsed correctly
	assert.Equal(t, "openai.OpenAI", cli.Scan.Generator)
	assert.Equal(t, []string{"test.Blank", "dan.Dan1"}, cli.Scan.Probe)
	assert.Equal(t, []string{"always.Always"}, cli.Scan.Detectors)
	assert.Equal(t, "always.*", cli.Scan.DetectorsGlob)
	assert.Equal(t, `{"model":"gpt-4"}`, cli.Scan.Config)
	assert.Equal(t, "custom.Harness", cli.Scan.Harness)
	assert.Equal(t, time.Hour, cli.Scan.Timeout)
	assert.Equal(t, "json", cli.Scan.Format)
	assert.Equal(t, "results.jsonl", filepath.Base(cli.Scan.Output))
	assert.Equal(t, "report.html", filepath.Base(cli.Scan.HTML))
	assert.True(t, cli.Scan.Verbose)
}

// TestScanCmdShortFlags tests short flag aliases work
func TestScanCmdShortFlags(t *testing.T) {
	var cli struct {
		Scan ScanCmd `cmd:""`
	}

	parser, err := kong.New(&cli,
		kong.Name("augustus"),
		kong.Exit(func(int) {}),
	)
	require.NoError(t, err)

	args := []string{
		"scan",
		"openai.OpenAI",
		"-p", "test.Blank",
		"-c", `{"model":"gpt-4"}`,
		"-f", "jsonl",
		"-o", "results.jsonl",
		"-v",
	}

	ctx, err := parser.Parse(args)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(ctx.Command(), "scan"))

	// Verify short flags work
	assert.Equal(t, []string{"test.Blank"}, cli.Scan.Probe)
	assert.Equal(t, `{"model":"gpt-4"}`, cli.Scan.Config)
	assert.Equal(t, "jsonl", cli.Scan.Format)
	assert.Equal(t, "results.jsonl", filepath.Base(cli.Scan.Output))
	assert.True(t, cli.Scan.Verbose)
}

// TestScanCmdDefaults tests default values are set correctly
func TestScanCmdDefaults(t *testing.T) {
	var cli struct {
		Scan ScanCmd `cmd:""`
	}

	parser, err := kong.New(&cli,
		kong.Name("augustus"),
		kong.Exit(func(int) {}),
	)
	require.NoError(t, err)

	args := []string{
		"scan",
		"openai.OpenAI",
		"--probe", "test.Blank",
	}

	ctx, err := parser.Parse(args)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(ctx.Command(), "scan"))

	// Verify defaults
	assert.Equal(t, "probewise.Probewise", cli.Scan.Harness)
	assert.Equal(t, 30*time.Minute, cli.Scan.Timeout)
	assert.Equal(t, "table", cli.Scan.Format)
}

// TestScanCmdFormatEnum tests format enum validation
func TestScanCmdFormatEnum(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		expectError bool
	}{
		{"table is valid", "table", false},
		{"json is valid", "json", false},
		{"jsonl is valid", "jsonl", false},
		{"invalid format", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cli struct {
				Scan ScanCmd `cmd:""`
			}

			parser, err := kong.New(&cli,
				kong.Name("augustus"),
				kong.Exit(func(int) {}),
			)
			require.NoError(t, err)

			args := []string{
				"scan",
				"openai.OpenAI",
				"--probe", "test.Blank",
				"--format", tt.format,
			}

			_, err = parser.Parse(args)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "--format")
				assert.Contains(t, err.Error(), "must be one of")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestVersionCmdRun tests VersionCmd.Run() method
func TestVersionCmdRun(t *testing.T) {
	// Note: version is a const, cannot be modified in tests
	// This test verifies the method doesn't error
	cmd := VersionCmd{}
	err := cmd.Run()
	assert.NoError(t, err)
	// Note: printVersion() writes to stdout, difficult to capture in unit test
	// Integration test would verify actual output
}

// TestHelpCmdRun tests HelpCmd.Run() method
func TestHelpCmdRun(t *testing.T) {
	var cli struct {
		Help HelpCmd `cmd:"" hidden:"" default:"1"`
		Scan ScanCmd `cmd:"" help:"Run scan."`
	}

	parser, err := kong.New(&cli,
		kong.Name("augustus"),
		kong.Description("Test CLI"),
	)
	require.NoError(t, err)

	// Parse to get context
	ctx, err := parser.Parse([]string{})
	require.NoError(t, err)

	// Capture help output
	var buf bytes.Buffer
	ctx.Kong.Stdout = &buf

	err = cli.Help.Run(ctx)
	assert.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "augustus")
	assert.Contains(t, output, "Test CLI")
}

// TestListCmdRun tests ListCmd.Run() method
func TestListCmdRun(t *testing.T) {
	// Note: listCapabilities() calls registry functions
	// This test verifies the command method works, but actual
	// capabilities listing requires full init() setup
	cmd := ListCmd{}
	err := cmd.Run()
	assert.NoError(t, err)
}

// TestScanCmdValidate tests the custom Validate() method
func TestScanCmdValidate(t *testing.T) {
	tests := []struct {
		name        string
		scan        ScanCmd
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid with probes",
			scan: ScanCmd{
				Generator: "openai.OpenAI",
				Probe:     []string{"test.Blank"},
			},
			expectError: false,
		},
		{
			name: "valid with probes-glob",
			scan: ScanCmd{
				Generator:  "openai.OpenAI",
				ProbesGlob: "dan.*",
			},
			expectError: false,
		},
		{
			name: "valid with all",
			scan: ScanCmd{
				Generator: "openai.OpenAI",
				All:       true,
			},
			expectError: false,
		},
		{
			name: "invalid: no probe selection",
			scan: ScanCmd{
				Generator: "openai.OpenAI",
			},
			expectError: true,
			errorMsg:    "at least one",
		},
		{
			name: "invalid: probe with probes-glob",
			scan: ScanCmd{
				Generator:  "openai.OpenAI",
				Probe:      []string{"test.Blank"},
				ProbesGlob: "dan.*",
			},
			expectError: true,
			errorMsg:    "cannot use --probe with --probes-glob",
		},
		{
			name: "invalid: probe with all",
			scan: ScanCmd{
				Generator: "openai.OpenAI",
				Probe:     []string{"test.Blank"},
				All:       true,
			},
			expectError: true,
			errorMsg:    "cannot use --probe with",
		},
		{
			name: "invalid: config-file and config",
			scan: ScanCmd{
				Generator:  "openai.OpenAI",
				Probe:      []string{"test.Blank"},
				ConfigFile: "config.yaml",
				Config:     `{"model":"gpt-4"}`,
			},
			expectError: true,
			errorMsg:    "cannot use both --config-file and --config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.scan.Validate()
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
