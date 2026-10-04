package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeSource(t *testing.T, src string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.go")
	require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
	return path
}

func TestConfigKeysReadResolvesConstants(t *testing.T) {
	path := writeSource(t, `package p

import "github.com/praetorian-inc/augustus/pkg/registry"

const (
	keyModel = "model"
	keyHost  = "host"
	keyTopP  = "top_p"
	keyAlias = "alias"
	keyFirst = "first"
)

func parse(m registry.Config) {
	_, _ = registry.RequireString(m, keyModel)
	_ = registry.GetString(m, keyHost, "default-is-not-a-key")
	_, _ = m[keyTopP].(float64)
	_ = registry.GetOptionalAPIKeyWithEnv(m, "ENV_VAR_IS_NOT_A_KEY")
	_ = pick(m, keyFirst, keyAlias)
}

func pick(m registry.Config, keys ...string) string {
	for _, k := range keys {
		if v := registry.GetString(m, k, ""); v != "" {
			return v
		}
	}
	return ""
}
`)

	keys, err := ConfigKeysRead(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"alias", "api_key", "first", "host", "model", "top_p"}, keys)
}

func TestConfigKeysReadRejectsRawLiteralKey(t *testing.T) {
	cases := map[string]string{
		"registry getter":  `registry.GetString(m, "endpoint", "")`,
		"index expression": `m["endpoint"]`,
		"local helper":     `helper(m, "endpoint")`,
		"method helper":    `reader{}.get(m, "endpoint")`,
	}
	for name, expr := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeSource(t, `package p

import "github.com/praetorian-inc/augustus/pkg/registry"

func helper(m registry.Config, key string) any { return m[key] }

type reader struct{}

func (reader) get(m registry.Config, key string) any { return m[key] }

func parse(m registry.Config) {
	_ = `+expr+`
}
`)
			_, err := ConfigKeysRead(path)
			require.Error(t, err)
			assert.Contains(t, err.Error(), `"endpoint"`)
		})
	}
}

func TestConfigKeysReadRejectsUnknownRegistryReader(t *testing.T) {
	path := writeSource(t, `package p

import "github.com/praetorian-inc/augustus/pkg/registry"

func parse(m registry.Config) {
	registry.WarnDeprecatedKeys(m)
}
`)
	_, err := ConfigKeysRead(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registry.WarnDeprecatedKeys")
}

func TestConfigKeysReadIgnoresMapWrites(t *testing.T) {
	path := writeSource(t, `package p

func describe(tm map[string]any) {
	tm["description"] = "a write, not a config read"
}
`)
	keys, err := ConfigKeysRead(path)
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// TestConfigKeysReadFailsClosed covers key shapes the guard cannot resolve to a
// package-level string constant: each must be an error, never a silent skip.
func TestConfigKeysReadFailsClosed(t *testing.T) {
	cases := map[string]struct{ decls, body, want string }{
		"local var key":           {body: "k := \"sneaky\"\n\t_ = m[k]", want: "m[k]"},
		"package var key":         {decls: "var keySneaky = \"sneaky\"", body: "_ = m[keySneaky]", want: "keySneaky"},
		"function-local const":    {body: "const keyLocal = \"sneaky\"\n\t_ = m[keyLocal]", want: "keyLocal"},
		"map[string]any helper":   {decls: "func readSneaky(x map[string]any) any { return x[\"sneaky\"] }", body: "_ = readSneaky(m)", want: `"sneaky"`},
		"alias of config map":     {body: "mm := m\n\t_ = mm[\"sneaky\"]", want: `"sneaky"`},
		"var alias of config map": {body: "var mm = m\n\t_ = mm[\"sneaky\"]", want: `"sneaky"`},
		"interface{} helper":      {decls: "func readSneaky(x map[string]interface{}) any { return x[\"sneaky\"] }", body: "_ = readSneaky(m)", want: `"sneaky"`},
		"alias with local key":    {body: "mm := m\n\tk := keyMode\n\t_ = mm[k]", want: "mm[k]"},
		"constant concatenation":  {body: "_ = m[keyMode+\"_x\"]", want: `keyMode + "_x"`},
		"registry getter var key": {body: "k := keyMode\n\t_ = registry.GetString(m, k, \"\")", want: "k"},
		"helper var key":          {decls: "func get(m registry.Config, key string) any { return m[key] }", body: "k := keyMode\n\t_ = get(m, k)", want: "k"},
		"config to foreign func":  {body: "_ = other.Read(m)", want: "other.Read"},
		"config to unknown func":  {body: "_ = undeclared(m)", want: "undeclared"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeSource(t, `package p

import (
	"example.com/other"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

const keyMode = "mode"

`+tc.decls+`

func parse(m registry.Config) {
	_ = m[keyMode]
	`+tc.body+`
}
`)
			_, err := ConfigKeysRead(path)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestConfigKeysReadAcceptsAliasAndCrossFileConstants(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keys.go"), []byte(`package p

const keyMode = "mode"
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.go"), []byte(`package p

func parse(m map[string]any) {
	mm := m
	_ = mm[keyMode]
}
`), 0o644))
	keys, err := ConfigKeysRead(filepath.Join(dir, "keys.go"), filepath.Join(dir, "config.go"))
	require.NoError(t, err)
	assert.Equal(t, []string{"mode"}, keys)
}

func TestPackageSourcesScansNewFilesAndHonoursExclusions(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644))
	}
	write("config.go", `package p

import "github.com/praetorian-inc/augustus/pkg/registry"

const (
	keyMode  = "mode"
	keyExtra = "extra"
	keyOther = "other"
)

func parse(m registry.Config) {
	_ = m[keyMode]
	_ = readExtra(m)
}
`)
	// A helper added in a brand-new file must be scanned without editing any list.
	write("extra.go", `package p

import "github.com/praetorian-inc/augustus/pkg/registry"

func readExtra(m registry.Config) any { return m[keyExtra] }
`)
	write("excluded.go", `package p

import "github.com/praetorian-inc/augustus/pkg/registry"

func parseOther(m registry.Config) any { return m[keyOther] }
`)
	write("config_test.go", `package p

import "github.com/praetorian-inc/augustus/pkg/registry"

func testOnly(m registry.Config) any { return m["test_only"] }
`)

	files, err := PackageSources(dir, "excluded.go")
	require.NoError(t, err)
	keys, err := ConfigKeysRead(files...)
	require.NoError(t, err)
	assert.Equal(t, []string{"extra", "mode"}, keys)

	_, err = PackageSources(dir, "gone.go")
	require.Error(t, err, "a stale exclusion must fail rather than silently match nothing")
	assert.Contains(t, err.Error(), "gone.go")
}
