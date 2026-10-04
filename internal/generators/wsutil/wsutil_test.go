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

	// Unterminated array index must error, not silently resolve the parent.
	_, err = ExtractField([]byte(`{"choices":[{"v":1}]}`), "choices[0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "malformed array index")
}

func TestConnectSucceeded(t *testing.T) {
	cases := []struct {
		status string
		want   bool
	}{
		{"HTTP/1.1 200 Connection established", true},
		{"HTTP/1.0 200 OK", true},
		{"HTTP/1.1 407 Proxy Authentication Required", false},
		{"HTTP/1.1 502 Bad Gateway", false},
		{"HTTP/1.1 407 needs 200 token", false}, // substring " 200" must not pass
		{"garbage", false},
		{"", false},
	}
	for _, tc := range cases {
		assert.Equalf(t, tc.want, connectSucceeded(tc.status), "status %q", tc.status)
	}
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

// TestMalformedURLErrorsRedactCredentials pins that both URL-parse error sites
// report a fixed message: url.Parse errors quote the userinfo (a password with
// no '@' is read as the port), so echoing them would leak credentials.
func TestMalformedURLErrorsRedactCredentials(t *testing.T) {
	sites := []struct {
		name    string
		wantErr string
		call    func(string) error
	}{
		{
			name:    "EnvProxyFor",
			wantErr: "websocket: invalid target url",
			call: func(raw string) error {
				_, err := EnvProxyFor(raw, nil)
				return err
			},
		},
		{
			name:    "BuildHandshakeConfig",
			wantErr: "websocket: invalid uri",
			call: func(raw string) error {
				_, err := BuildHandshakeConfig(raw, "", nil, nil, false)
				return err
			},
		},
	}
	inputs := []string{
		"ws://user:s3cret@host:bad",
		"ws://user:s3cret", // no '@': url.Parse reads the password as the port
	}
	for _, site := range sites {
		for _, raw := range inputs {
			t.Run(site.name+"/"+raw, func(t *testing.T) {
				err := site.call(raw)
				require.ErrorContains(t, err, site.wantErr)
				assert.NotContains(t, err.Error(), "s3cret", "error leaks the URL password")
				assert.NotContains(t, err.Error(), "user:", "error leaks the URL userinfo")
			})
		}
	}
}
