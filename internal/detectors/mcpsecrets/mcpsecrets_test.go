package mcpsecrets

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestNewCredential(t *testing.T) {
	d, err := NewCredential(registry.Config{})
	if err != nil {
		t.Fatalf("NewCredential() error = %v", err)
	}
	if d == nil {
		t.Fatal("NewCredential() returned nil detector")
	}
	if d.Name() != "mcpsecrets.Credential" {
		t.Errorf("Name() = %q, want %q", d.Name(), "mcpsecrets.Credential")
	}
	if d.Description() == "" {
		t.Error("Description() returned empty string")
	}
}

func TestCredential_Detect(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   float64
	}{
		// --- Positive: provider-prefixed keys embedded in MCP config ---
		{
			name:   "aws access key in env block",
			output: `{"mcpServers":{"s3":{"command":"srv","env":{"AWS_ACCESS_KEY_ID":"AKIA1234567890ABCDEF"}}}}`,
			want:   1.0,
		},
		{
			name:   "github token in env block",
			output: `{"mcpServers":{"gh":{"env":{"GITHUB_TOKEN":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}}}}`,
			want:   1.0,
		},
		{
			name:   "openai key in env block",
			output: `{"env":{"OPENAI_API_KEY":"sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV"}}`,
			want:   1.0,
		},
		{
			name: "slack bot token",
			// Synthetic, non-structured value: matches the xoxb- prefix pattern
			// but avoids Slack's real numeric-segment format so secret scanners
			// (e.g. GitHub push protection) don't flag this fixture.
			output: `SLACK_BOT_TOKEN=xoxb-SYNTHETICfaketoken000notreal`,
			want:   1.0,
		},
		// --- Positive: config-field-aware (non-provider-format values) ---
		{
			name:   "concrete db password field",
			output: `{"mcpServers":{"db":{"env":{"DB_PASSWORD":"S3cr3tP@ssw0rd!"}}}}`,
			want:   1.0,
		},
		// --- Review finding A: SafeTokens must match config VALUES by EXACT
		// equality, not substring. A real secret that merely CONTAINS a safe-token
		// word ("mypassword" is a SafeToken) is a true secret, not a placeholder. ---
		{
			name:   "password containing safe-token substring is still a secret",
			output: `{"env":{"DB_PASSWORD":"mypassword123!"}}`,
			want:   1.0,
		},
		// --- Review finding B: a non-secret key that merely CONTAINS a secret word
		// ("tokenizer"/"tokenized" contain "token") must NOT gate value inspection;
		// only whole key segments (or a compound key regex) count. ---
		{
			name:   "tokenizer key is not a secret key (json)",
			output: `{"env":{"tokenizer":"cl100k_base"}}`,
			want:   0.0,
		},
		{
			name:   "tokenized key is not a secret key (yaml)",
			output: `tokenized: gpt2`,
			want:   0.0,
		},
		{
			name:   "credentials embedded in connection string",
			output: `{"env":{"DATABASE_URL":"postgres://admin:S3cr3tP@ss@db.internal:5432/app"}}`,
			want:   1.0,
		},
		{
			name:   "env-style client secret assignment",
			output: `OAUTH_CLIENT_SECRET=9f8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d`,
			want:   1.0,
		},
		{
			name:   "real key wins over placeholder in same file",
			output: `{"env":{"NOTE":"your_api_key_here","GITHUB_TOKEN":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}}`,
			want:   1.0,
		},
		// --- Positive: high-entropy values that superficially contain placeholder words (FIX 2) ---
		{
			name:   "password containing angle bracket is still a secret",
			output: `{"env":{"DB_PASSWORD":"Str0ng<Pass9times"}}`,
			want:   1.0,
		},
		{
			name:   "password starting with none is still a secret",
			output: `{"env":{"DB_PASSWORD":"none0fyourbus1ness42"}}`,
			want:   1.0,
		},
		{
			name:   "password starting with todo is still a secret",
			output: `{"env":{"DB_PASSWORD":"todoR3member9This"}}`,
			want:   1.0,
		},
		{
			name:   "two secrets in one output",
			output: `{"env":{"DB_PASSWORD":"Str0ng<Pass9times","GITHUB_TOKEN":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}}`,
			want:   1.0,
		},
		// --- Negative: non-secret literals assigned to secret-named keys (FIX 1) ---
		{
			name:   "boolean flag on secret-named key",
			output: `PASSWORD_REQUIRED=true`,
			want:   0.0,
		},
		{
			name:   "boolean false on token key",
			output: `DEBUG_TOKEN=false`,
			want:   0.0,
		},
		{
			name:   "log level on credential key",
			output: `CREDENTIAL_CACHE=memory`,
			want:   0.0,
		},
		{
			name:   "hostname on password key",
			output: `{"env":{"DB_PASSWORD":"localhost"}}`,
			want:   0.0,
		},
		{
			name:   "require literal on client secret",
			output: `{"env":{"CLIENT_SECRET":"require"}}`,
			want:   0.0,
		},
		{
			name:   "disabled literal on password key",
			output: `{"env":{"DB_PASSWORD":"disabled"}}`,
			want:   0.0,
		},
		{
			name:   "version string on token key",
			output: `{"env":{"API_TOKEN":"1.2.3"}}`,
			want:   0.0,
		},
		// --- Negative: delimiter-trailing whitespace must not cross a newline
		// (FIX 1). A benign secret-named PARENT key whose child is on the NEXT
		// line must NOT spill the child onto the parent's value capture. ---
		{
			name: "yaml secret-named parent with child on next line",
			output: `credentials:
  note: none configured for this environment`,
			want: 0.0,
		},
		{
			name: "yaml token-substring parent with child on next line",
			output: `tokenizer:
  model: gpt-4`,
			want: 0.0,
		},
		{
			name: "env empty secret value does not spill onto next line",
			output: `DB_PASSWORD=
SERVICE_NAME=my-billing-service-prod`,
			want: 0.0,
		},
		// --- Negative: entropy / version / all-digit gates on secret-named
		// keys (FIX 2 — pins looksHighEntropy / versionString / allDigits). ---
		{
			name:   "low-entropy value on password key",
			output: `{"env":{"DB_PASSWORD":"aaaaaaaaaa"}}`,
			want:   0.0,
		},
		{
			name:   "dotted version string on token key",
			output: `{"env":{"API_TOKEN":"1.2.3.4.5.6"}}`,
			want:   0.0,
		},
		{
			name:   "all-digit value on token key",
			output: `{"env":{"API_TOKEN":"12345678"}}`,
			want:   0.0,
		},
		// --- Negative: credential-free DSN / connection string (FIX 3) ---
		{
			name:   "credential-free dsn key",
			output: `DSN=postgres://localhost:5432/app`,
			want:   0.0,
		},
		{
			name:   "connection string without userinfo password",
			output: `{"env":{"CONNECTION_STRING":"postgres://localhost/app"}}`,
			want:   0.0,
		},
		{
			name:   "provider-format value that is a safe token",
			output: `{"env":{"OPENAI_API_KEY":"sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}}`,
			want:   0.0,
		},
		// --- Negative: safe / placeholder / references / benign ---
		{
			name:   "env var reference braces",
			output: `{"env":{"API_KEY":"${OPENAI_API_KEY}"}}`,
			want:   0.0,
		},
		{
			name:   "env var reference dollar",
			output: `{"env":{"API_KEY":"$OPENAI_API_KEY"}}`,
			want:   0.0,
		},
		{
			name:   "documented placeholder token",
			output: `{"env":{"API_KEY":"your_api_key_here"}}`,
			want:   0.0,
		},
		{
			name:   "changeme password placeholder",
			output: `{"env":{"DB_PASSWORD":"changeme"}}`,
			want:   0.0,
		},
		{
			name:   "benign config no secrets",
			output: `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/data"]}}}`,
			want:   0.0,
		},
		{
			name:   "uuid server identifier is not a secret",
			output: `{"mcpServers":{"svc":{"id":"550e8400-e29b-41d4-a716-446655440000","command":"srv"}}}`,
			want:   0.0,
		},
		// --- Positive: YAML/INI unquoted key: value secrets (FIX A) ---
		{
			name:   "yaml password key value",
			output: `DB_PASSWORD: S3cr3tP@ssw0rd!`,
			want:   1.0,
		},
		{
			name: "yaml secret inside a multi-line block",
			output: `mcp:
  db:
    DB_PASSWORD: S3cr3tP@ssw0rd!
    LOG_LEVEL: debug`,
			want: 1.0,
		},
		// --- Negative: YAML non-secret / reference values (FIX A) ---
		{
			name:   "yaml log level is not a secret",
			output: `LOG_LEVEL: debug`,
			want:   0.0,
		},
		{
			name:   "yaml env-var reference is not a secret",
			output: `API_KEY: ${OPENAI_KEY}`,
			want:   0.0,
		},
		// --- Regression: yamlKV must not alter JSON scoring (FIX A) ---
		{
			name: "pretty printed json secret still flagged",
			output: `{
  "mcpServers": {
    "db": {
      "env": {
        "DB_PASSWORD": "S3cr3tP@ssw0rd!"
      }
    }
  }
}`,
			want: 1.0,
		},
		{
			name: "pretty printed json placeholder still safe",
			output: `{
  "mcpServers": {
    "db": {
      "env": {
        "DB_PASSWORD": "changeme"
      }
    }
  }
}`,
			want: 0.0,
		},
		// --- Negative: URL port must not be treated as a password (FIX B) ---
		{
			name:   "url port is not a connection-string password",
			output: `https://example.com:443@tracker/x`,
			want:   0.0,
		},
		{
			name:   "real userinfo password still flagged",
			output: `postgres://admin:S3cr3tP@ss@db.internal:5432/prod`,
			want:   1.0,
		},
		// --- Review finding (FN): a userinfo credential that OMITS the username
		// (empty username, e.g. "redis://:secret@host") must still be caught by
		// connCreds. REDIS_URL is not itself a secret key (its last segment "url"
		// is a pointer word), so this can only fire via the connCreds signal. ---
		{
			name:   "username-less redis connection string password",
			output: `{"env":{"REDIS_URL":"redis://:S3cr3tP@ss@db.internal:6379"}}`,
			want:   1.0,
		},
		// --- Positive: jsonKV value with an escaped quote captured in full (FIX G) ---
		{
			name:   "json value with escaped quote",
			output: `{"password":"pa\"ss9word1x"}`,
			want:   1.0,
		},
		// --- Review finding A: secrets passed as command-line flags in args arrays.
		// Both the "--flag=value" form and the JSON "--flag","value" pair form. ---
		{
			name:   "args flag pair password",
			output: `{"mcpServers":{"db":{"command":"srv","args":["--password","S3cr3tP@ssw0rd!"]}}}`,
			want:   1.0,
		},
		{
			name:   "args flag pair api-key",
			output: `{"args":["--api-key","abcD1234EFgh5678"]}`,
			want:   1.0,
		},
		{
			name:   "args flag pair token",
			output: `{"args":["--token","S3cr3tT0ken!value"]}`,
			want:   1.0,
		},
		{
			name:   "args flag equals api-key",
			output: `["--api-key=abcD1234!"]`,
			want:   1.0,
		},
		{
			name:   "args flag equals password",
			output: `--password=S3cr3tP@ssw0rd!`,
			want:   1.0,
		},
		{
			name:   "args flag equals token",
			output: `{"args":["--token=S3cr3tT0ken!value"]}`,
			want:   1.0,
		},
		{
			name:   "benign verbose flag",
			output: `{"args":["--verbose"]}`,
			want:   0.0,
		},
		{
			name:   "benign model flag pair",
			output: `{"args":["--model","gpt-4"]}`,
			want:   0.0,
		},
		{
			name:   "benign model flag equals",
			output: `--model=gpt-4`,
			want:   0.0,
		},
		// --- Review finding B: a bare URL/URI value under a secret-ish key is an
		// endpoint, not a credential; real embedded URI creds still caught by connCreds. ---
		{
			name:   "token endpoint url is not a secret",
			output: `TOKEN_ENDPOINT=https://issuer.example.com/oauth/token`,
			want:   0.0,
		},
		{
			name:   "password reset url is not a secret",
			output: `PASSWORD_RESET_URL=https://x/y`,
			want:   0.0,
		},
		{
			name:   "database url with userinfo credentials still flagged",
			output: `DATABASE_URL=postgres://admin:S3cr3tP@ss@h/db`,
			want:   1.0,
		},
		// --- Review finding C: TOML/INI keys with '-' and '.' separators. ---
		{
			name:   "toml client-secret key",
			output: `client-secret = "S3cr3tP@ssw0rd!"`,
			want:   1.0,
		},
		{
			name:   "toml dotted database.password key",
			output: `database.password = "S3cr3tP@ssw0rd!"`,
			want:   1.0,
		},
		// --- Review finding D: YAML sequence item ("- key: value"). ---
		{
			name:   "yaml sequence item password",
			output: `  - password: S3cr3tP@ssw0rd!`,
			want:   1.0,
		},
		// --- Review finding E: long alphabetic passphrase (no digit/special/mixed
		// case) on a secret-named key is still a concrete secret when >= 16 chars. ---
		{
			name:   "long alphabetic passphrase on password key",
			output: `DB_PASSWORD=CORRECTHORSEBATTERYSTAPLE`,
			want:   1.0,
		},
		{
			name:   "short low-entropy word on password key stays clean",
			output: `DB_PASSWORD=hunter`,
			want:   0.0,
		},
		// --- Review finding 1: inline comments after an env/YAML value must be
		// stripped before gating, so the deny-list / entropy screens see the value
		// alone (not the comment punctuation). A '#' with no preceding whitespace
		// (part of the value, not a comment) is preserved. ---
		{
			name:   "env inline comment after boolean value stripped",
			output: `PASSWORD_REQUIRED=false # local dev only`,
			want:   0.0,
		},
		{
			name:   "yaml value that is only a comment is empty",
			output: `api_key: # see documentation`,
			want:   0.0,
		},
		{
			name:   "hash inside env value with no preceding space is preserved",
			output: `DB_PASSWORD=Str0ng#Pass9x`,
			want:   1.0,
		},
		// --- Review finding 2: a key whose LAST segment is a pointer word (file,
		// path, ref, location, dir, uri, url, endpoint) references WHERE a secret
		// lives, not the secret itself, and must not be flagged. ---
		{
			name:   "api key file pointer is not the secret",
			output: `{"env":{"API_KEY_FILE":"/var/run/secrets/x.json"}}`,
			want:   0.0,
		},
		{
			name:   "client secret path pointer is not the secret",
			output: `{"env":{"client_secret_path":"/tmp/client.json"}}`,
			want:   0.0,
		},
		{
			name:   "github api key positive still fires (not a pointer)",
			output: `{"env":{"GITHUB_API_KEY":"abcD1234EFgh5678"}}`,
			want:   1.0,
		},
		{
			name:   "access token positive still fires (not a pointer)",
			output: `{"env":{"access_token":"abcD1234EFgh5678"}}`,
			want:   1.0,
		},
		// --- Review finding 4: a "--flag=value" passed as ONE quoted JSON argv
		// element may contain spaces; the whole value must be captured. ---
		{
			name:   "arg flag equals value with spaces",
			output: `{"args":["--passphrase=correct horse battery staple"]}`,
			want:   1.0,
		},
		// --- Review finding 1: camelCase key segmentation. Keys must split at
		// camelCase transitions as well as [_.\-], so "dbPassword" decomposes to
		// {db,password} (FN fixed), "apiToken" to {api,token}, and "apiKeyFile" to
		// {api,key,file} whose pointer last-segment stops the FP. ---
		{
			name:   "camelcase db password key",
			output: `{"env":{"dbPassword":"S3cr3tP@ssw0rd!"}}`,
			want:   1.0,
		},
		{
			name:   "camelcase api token key",
			output: `{"env":{"apiToken":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}}`,
			want:   1.0,
		},
		{
			name:   "camelcase api key file pointer is not the secret",
			output: `{"env":{"apiKeyFile":"/var/run/secrets/x"}}`,
			want:   0.0,
		},
		{
			name:   "camelcase client secret path pointer is not the secret",
			output: `{"env":{"clientSecretPath":"/tmp/client.json"}}`,
			want:   0.0,
		},
		// --- Review finding 2: escaped quote inside a quoted arg value must be
		// captured in full (escape-aware capture), not truncated at the backslash. ---
		{
			name:   "args flag pair value with escaped quote",
			output: `["--password","S3c\"r3tValue!"]`,
			want:   1.0,
		},
		// --- Review finding 4: a quoted env/YAML value carrying a legit ' #' must
		// NOT be treated as an inline comment (only UNQUOTED values are stripped). ---
		{
			name:   "quoted env value with hash is not comment-stripped",
			output: `DB_PASSWORD="my #secret9times"`,
			want:   1.0,
		},
		{
			name:   "empty output",
			output: ``,
			want:   0.0,
		},
	}

	d, err := NewCredential(registry.Config{})
	if err != nil {
		t.Fatalf("NewCredential() error = %v", err)
	}
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &attempt.Attempt{Outputs: []string{tt.output}}
			scores, err := d.Detect(ctx, a)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if len(scores) != 1 {
				t.Fatalf("Detect() returned %d scores, want 1", len(scores))
			}
			if scores[0] != tt.want {
				t.Errorf("Detect() = %v, want %v\noutput: %s", scores[0], tt.want, tt.output)
			}
		})
	}
}

func TestCredential_Detect_ZeroOutputsYieldsZeroScores(t *testing.T) {
	d, _ := NewCredential(registry.Config{})
	a := &attempt.Attempt{Outputs: nil}
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(scores) != 0 {
		t.Fatalf("got %d scores, want 0 for zero outputs", len(scores))
	}
}

// FIX 5: the connection-string password must be captured greedily up to the
// LAST '@' before the host, so a password that itself contains '@' is intact.
func TestConnCredsCapturesPasswordUpToLastAt(t *testing.T) {
	const uri = `postgres://admin:S3cr3tP@ss@db.internal:5432/app`
	m := connCreds.FindStringSubmatch(uri)
	if m == nil {
		t.Fatalf("connCreds did not match %q", uri)
	}
	if m[1] != "S3cr3tP@ss" {
		t.Errorf("captured password = %q, want %q", m[1], "S3cr3tP@ss")
	}
}

func TestCredential_Detect_PreservesOutputOrderAndLength(t *testing.T) {
	d, _ := NewCredential(registry.Config{})
	a := &attempt.Attempt{Outputs: []string{
		`clean config`,
		`GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789`,
		`another clean line`,
	}}
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	want := []float64{0.0, 1.0, 0.0}
	if len(scores) != len(want) {
		t.Fatalf("got %d scores, want %d", len(scores), len(want))
	}
	for i := range want {
		if scores[i] != want[i] {
			t.Errorf("scores[%d] = %v, want %v", i, scores[i], want[i])
		}
	}
}
