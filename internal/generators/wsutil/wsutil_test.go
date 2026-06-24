package wsutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractField(t *testing.T) {
	cases := []struct {
		name  string
		frame string
		path  string
		want  string
	}{
		{"simple", `{"text":"hi"}`, "text", "hi"},
		{"dotted", `{"data":{"text":"deep"}}`, "data.text", "deep"},
		{"jsonpath_prefix", `{"data":{"text":"deep"}}`, "$.data.text", "deep"},
		{"array_index", `{"choices":[{"content":"a"},{"content":"b"}]}`, "choices[1].content", "b"},
		{"number", `{"n":42}`, "n", "42"},
		{"float", `{"n":3.5}`, "n", "3.5"},
		{"bool", `{"b":true}`, "b", "true"},
		{"object_remarshal", `{"obj":{"k":1}}`, "obj", `{"k":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExtractField([]byte(tc.frame), tc.path)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestExtractField_Errors(t *testing.T) {
	_, err := ExtractField([]byte("not json"), "text")
	assert.Error(t, err)

	_, err = ExtractField([]byte(`{"a":1}`), "missing")
	assert.Error(t, err)

	_, err = ExtractField([]byte(`{"a":1}`), "a.b")
	assert.Error(t, err)

	_, err = ExtractField([]byte(`{"a":[1]}`), "a[5]")
	assert.Error(t, err)
}

func TestExtractFirst(t *testing.T) {
	frame := []byte(`{"legacy":{"text":"ok"}}`)
	got, ok := ExtractFirst(frame, []string{"$.modern.text", "$.legacy.text"})
	assert.True(t, ok)
	assert.Equal(t, "ok", got)

	_, ok = ExtractFirst(frame, []string{"$.a", "$.b"})
	assert.False(t, ok)
}

func TestJSONEscape(t *testing.T) {
	assert.Equal(t, `he said \"hi\"`, JSONEscape(`he said "hi"`))
	assert.Equal(t, `line1\nline2`, JSONEscape("line1\nline2"))
}

func TestBuildHandshakeConfig(t *testing.T) {
	cfg, err := BuildHandshakeConfig("wss://host/ws", "", map[string]string{"Authorization": "Bearer x"}, []string{"graphql-transport-ws"}, true)
	require.NoError(t, err)
	assert.Equal(t, "https://host", cfg.Origin.String()) // auto-derived
	assert.Equal(t, "Bearer x", cfg.Header.Get("Authorization"))
	assert.Equal(t, []string{"graphql-transport-ws"}, cfg.Protocol)
	assert.True(t, cfg.TlsConfig.InsecureSkipVerify)

	_, err = BuildHandshakeConfig("http://host", "", nil, nil, false)
	assert.Error(t, err) // wrong scheme
}

func TestJoinRaw(t *testing.T) {
	assert.Nil(t, JoinRaw(nil))
	assert.Equal(t, []byte("only"), JoinRaw([][]byte{[]byte("only")}))
	assert.Equal(t, []byte("a\nb"), JoinRaw([][]byte{[]byte("a"), []byte("b")}))
}
