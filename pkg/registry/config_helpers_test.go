package registry

import (
	"testing"
)

func TestGetString(t *testing.T) {
	cfg := Config{"name": "test", "empty": ""}

	if got := GetString(cfg, "name", "default"); got != "test" {
		t.Errorf("GetString(name) = %q, want %q", got, "test")
	}
	if got := GetString(cfg, "empty", "default"); got != "" {
		t.Errorf("GetString(empty) = %q, want %q", got, "")
	}
	if got := GetString(cfg, "missing", "default"); got != "default" {
		t.Errorf("GetString(missing) = %q, want %q", got, "default")
	}
}

func TestGetInt(t *testing.T) {
	cfg := Config{
		"int_val":   100,
		"float_val": 200.0, // JSON numbers are float64
		"zero":      0,
	}

	if got := GetInt(cfg, "int_val", -1); got != 100 {
		t.Errorf("GetInt(int_val) = %d, want %d", got, 100)
	}
	if got := GetInt(cfg, "float_val", -1); got != 200 {
		t.Errorf("GetInt(float_val) = %d, want %d", got, 200)
	}
	if got := GetInt(cfg, "zero", -1); got != 0 {
		t.Errorf("GetInt(zero) = %d, want %d", got, 0)
	}
	if got := GetInt(cfg, "missing", -1); got != -1 {
		t.Errorf("GetInt(missing) = %d, want %d", got, -1)
	}
}

func TestGetFloat64(t *testing.T) {
	cfg := Config{
		"float_val": 0.7,
		"int_val":   100,
		"zero":      0.0,
	}

	if got := GetFloat64(cfg, "float_val", 0.0); got != 0.7 {
		t.Errorf("GetFloat64(float_val) = %f, want %f", got, 0.7)
	}
	if got := GetFloat64(cfg, "int_val", 0.0); got != 100.0 {
		t.Errorf("GetFloat64(int_val) = %f, want %f", got, 100.0)
	}
	if got := GetFloat64(cfg, "zero", 1.0); got != 0.0 {
		t.Errorf("GetFloat64(zero) = %f, want %f", got, 0.0)
	}
	if got := GetFloat64(cfg, "missing", 0.5); got != 0.5 {
		t.Errorf("GetFloat64(missing) = %f, want %f", got, 0.5)
	}
}

func TestGetBool(t *testing.T) {
	cfg := Config{"enabled": true, "disabled": false}

	if got := GetBool(cfg, "enabled", false); got != true {
		t.Errorf("GetBool(enabled) = %t, want %t", got, true)
	}
	if got := GetBool(cfg, "disabled", true); got != false {
		t.Errorf("GetBool(disabled) = %t, want %t", got, false)
	}
	if got := GetBool(cfg, "missing", true); got != true {
		t.Errorf("GetBool(missing) = %t, want %t", got, true)
	}
}

func TestGetStringSlice(t *testing.T) {
	cfg := Config{
		"strings": []string{"a", "b", "c"},
		"any":     []any{"x", "y", "z"},
		"empty":   []string{},
	}

	got := GetStringSlice(cfg, "strings", nil)
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("GetStringSlice(strings) length = %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("GetStringSlice(strings)[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	got = GetStringSlice(cfg, "any", nil)
	want = []string{"x", "y", "z"}
	if len(got) != len(want) {
		t.Fatalf("GetStringSlice(any) length = %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("GetStringSlice(any)[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	got = GetStringSlice(cfg, "empty", []string{"default"})
	if len(got) != 0 {
		t.Errorf("GetStringSlice(empty) = %v, want empty slice", got)
	}

	got = GetStringSlice(cfg, "missing", []string{"default"})
	if len(got) != 1 || got[0] != "default" {
		t.Errorf("GetStringSlice(missing) = %v, want [default]", got)
	}
}

func TestRequireString(t *testing.T) {
	cfg := Config{"name": "test"}

	val, err := RequireString(cfg, "name")
	if err != nil {
		t.Fatalf("RequireString(name) error = %v, want nil", err)
	}
	if val != "test" {
		t.Errorf("RequireString(name) = %q, want %q", val, "test")
	}

	_, err = RequireString(cfg, "missing")
	if err == nil {
		t.Fatal("RequireString(missing) error = nil, want error")
	}
	if errMsg := err.Error(); errMsg == "" {
		t.Error("error message is empty")
	}
}
