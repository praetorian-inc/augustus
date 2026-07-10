# REST Two-Step Image-Upload Flows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the generic `rest.Rest` generator run a pre-request image *upload*, capture a handle/URL from the upload response, and substitute it into the follow-up "analyze" request — enabling presigned-URL / object-store / async-OCR two-step multimodal flows without shell scripts.

**Architecture:** Refactor the three existing request builders to take a per-request `requestSpec` value instead of reading generator fields directly, so the same builders serve both the main request and a new upload request. Add an optional `upload` config block (`uploadConfig`) parsed and validated in `NewRest`. In `callAPI`, when `upload` is set and an image is attached, run `doUpload` first: it builds the upload request via the shared builders, sends the image, and captures named values (JSONPath into the body, or `header:Name`) into the hook-var map. The main request then builds with the image omitted and the captured `$VAR`s substituted into its URI, body, and headers.

**Tech Stack:** Go, `net/http`, `net/http/httptest`, `testify` (`require`/`assert`), existing `pkg/attempt`, `pkg/registry`, `pkg/types` packages.

## Global Constraints

- Module path: `github.com/praetorian-inc/augustus`.
- All work is confined to `internal/generators/rest/` (`rest.go`, `rest_test.go`).
- Keep the tree `golangci-lint fmt`-clean (gofumpt + goimports). Run `golangci-lint fmt ./...` before each commit if available; otherwise `gofmt -w`.
- Build must pass: `go build ./...`. Tests run with race detection: `go test ./internal/generators/rest/ -race`.
- Conventional commits (`feat:`, `refactor:`, `test:`).
- Commit message trailer (per repo convention):
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- Captured-var keys reuse the hook-var key rule `^[A-Z0-9_]+$` and the existing `$KEY`
  substitution path (`populateTemplate`), which JSON-escapes values.
- Work happens on branch `feat/lab-4174-rest-two-step-image-upload` (already created).
- `registry.Config` is `map[string]any`.

---

### Task 1: Refactor request builders to take a `requestSpec`

Pure behavior-preserving refactor. Today `buildRequest`, `buildTemplateRequest`, `buildRawBinaryRequest`, `buildMultipartRequest`, and `applyHeaders` read `r.uri`/`r.method`/`r.headers`/`r.reqTemplate`/`r.bodyMode`/`r.multipart` directly. Introduce a `requestSpec` struct carrying those per-request fields so the builders can serve any request. Also add URI templating (the URI now runs through `populateTemplate`) and a nil-`conv` guard for `$MESSAGES`. All existing tests must stay green.

**Files:**
- Modify: `internal/generators/rest/rest.go` (builders around L457-621)
- Test: `internal/generators/rest/rest_test.go` (existing suite is the regression guard)

**Interfaces:**
- Produces:
  - `type requestSpec struct { uri, method string; headers map[string]string; reqTemplate, bodyMode string; multipart *multipartConfig }`
  - `func (r *Rest) mainSpec() requestSpec`
  - `func (r *Rest) buildRequest(ctx context.Context, spec requestSpec, conv *attempt.Conversation, prompt string, hookVars map[string]string, img *attempt.Image) (*http.Request, error)`
  - `func (r *Rest) buildTemplateRequest(ctx context.Context, spec requestSpec, conv *attempt.Conversation, prompt string, hookVars map[string]string, img *attempt.Image) (*http.Request, error)`
  - `func (r *Rest) buildRawBinaryRequest(ctx context.Context, spec requestSpec, prompt string, hookVars map[string]string, img *attempt.Image) (*http.Request, error)`
  - `func (r *Rest) buildMultipartRequest(ctx context.Context, spec requestSpec, prompt string, hookVars map[string]string, img *attempt.Image) (*http.Request, error)`
  - `func (r *Rest) applyHeaders(req *http.Request, headers map[string]string, prompt string, hookVars map[string]string)`

- [ ] **Step 1: Add the `requestSpec` type and `mainSpec` helper**

Insert near the `multipartConfig` type (after L89 in `rest.go`):

```go
// requestSpec carries the per-request fields the builders need, so the same
// builders serve both the main ("analyze") request and the pre-request upload.
type requestSpec struct {
	uri         string
	method      string
	headers     map[string]string
	reqTemplate string
	bodyMode    string
	multipart   *multipartConfig
}

// mainSpec returns the requestSpec for the generator's primary request,
// populated from the top-level configuration.
func (r *Rest) mainSpec() requestSpec {
	return requestSpec{
		uri:         r.uri,
		method:      r.method,
		headers:     r.headers,
		reqTemplate: r.reqTemplate,
		bodyMode:    r.bodyMode,
		multipart:   r.multipart,
	}
}
```

- [ ] **Step 2: Rewrite `buildRequest` to dispatch on the spec and template the URI**

Replace the existing `buildRequest` (L461-476) with:

```go
// buildRequest constructs an outgoing HTTP request for spec, dispatching on the
// spec's image-transport mode. The spec's URI is run through populateTemplate so
// $INPUT/$KEY/hook/captured vars (e.g. /analyze/$FILE_ID) resolve. Image bytes
// (when an image is attached) are placed on the wire per mode; encode errors are
// surfaced (wrapped), never silently dropped.
func (r *Rest) buildRequest(
	ctx context.Context,
	spec requestSpec,
	conv *attempt.Conversation,
	prompt string,
	hookVars map[string]string,
	img *attempt.Image,
) (*http.Request, error) {
	spec.uri = r.populateTemplate(spec.uri, prompt, hookVars)
	switch {
	case spec.bodyMode == bodyModeRawBinary:
		return r.buildRawBinaryRequest(ctx, spec, prompt, hookVars, img)
	case spec.multipart != nil:
		return r.buildMultipartRequest(ctx, spec, prompt, hookVars, img)
	default:
		return r.buildTemplateRequest(ctx, spec, conv, prompt, hookVars, img)
	}
}
```

- [ ] **Step 3: Update `buildTemplateRequest` to use `spec` and guard nil `conv`**

Replace the body of `buildTemplateRequest` (L482-525) with (note `r.reqTemplate`→`spec.reqTemplate`, `r.method`→`spec.method`, `r.uri`→`spec.uri`, `r.applyHeaders(req, ...)`→`r.applyHeaders(req, spec.headers, ...)`, and the `conv != nil` guard):

```go
func (r *Rest) buildTemplateRequest(
	ctx context.Context,
	spec requestSpec,
	conv *attempt.Conversation,
	prompt string,
	hookVars map[string]string,
	img *attempt.Image,
) (*http.Request, error) {
	body := r.populateTemplate(spec.reqTemplate, prompt, hookVars)

	// Replace $MESSAGES with the full conversation as a JSON array. Guarded on a
	// non-nil conv because the upload pre-request may build without one.
	if conv != nil && strings.Contains(body, "$MESSAGES") {
		body = strings.ReplaceAll(body, "$MESSAGES", conversationToJSON(conv))
	}

	if img != nil && strings.Contains(body, "$IMAGE_") {
		b64, err := img.ToBase64()
		if err != nil {
			return nil, fmt.Errorf("rest: encode image: %w", err)
		}
		body = strings.ReplaceAll(body, "$IMAGE_DATAURI", "data:"+img.MimeType+";base64,"+b64)
		body = strings.ReplaceAll(body, "$IMAGE_B64", b64)
		body = strings.ReplaceAll(body, "$IMAGE_MIME", img.MimeType)
	}

	var req *http.Request
	var err error
	if spec.method == "GET" {
		req, err = http.NewRequestWithContext(ctx, spec.method, spec.uri+"?"+body, nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, spec.method, spec.uri, bytes.NewBufferString(body))
	}
	if err != nil {
		return nil, fmt.Errorf("rest: failed to create request: %w", err)
	}

	r.applyHeaders(req, spec.headers, prompt, hookVars)
	return req, nil
}
```

- [ ] **Step 4: Update `buildRawBinaryRequest` and `buildMultipartRequest` to use `spec`**

Replace `buildRawBinaryRequest` (L531-554) with:

```go
func (r *Rest) buildRawBinaryRequest(
	ctx context.Context,
	spec requestSpec,
	prompt string,
	hookVars map[string]string,
	img *attempt.Image,
) (*http.Request, error) {
	if img == nil {
		return nil, fmt.Errorf("rest: body_mode raw_binary requires an image attachment")
	}

	data, err := img.Bytes()
	if err != nil {
		return nil, fmt.Errorf("rest: read image bytes: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, spec.method, spec.uri, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("rest: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", img.MimeType)
	r.applyHeaders(req, spec.headers, prompt, hookVars)
	return req, nil
}
```

Replace `buildMultipartRequest` (L562-614) — change signature to take `spec`, and replace every `r.multipart` with `spec.multipart`, `r.method`/`r.uri` with `spec.method`/`spec.uri`, and `r.applyHeaders(req, prompt, hookVars)` with `r.applyHeaders(req, spec.headers, prompt, hookVars)`:

```go
func (r *Rest) buildMultipartRequest(
	ctx context.Context,
	spec requestSpec,
	prompt string,
	hookVars map[string]string,
	img *attempt.Image,
) (*http.Request, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	keys := make([]string, 0, len(spec.multipart.fields))
	for k := range spec.multipart.fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		value := r.populateTemplate(spec.multipart.fields[k], prompt, hookVars)
		if err := writer.WriteField(k, value); err != nil {
			return nil, fmt.Errorf("rest: write multipart field %q: %w", k, err)
		}
	}

	if img != nil {
		data, err := img.Bytes()
		if err != nil {
			return nil, fmt.Errorf("rest: read image bytes: %w", err)
		}
		header := textproto.MIMEHeader{}
		header.Set("Content-Disposition", fmt.Sprintf(
			`form-data; name=%q; filename=%q`, spec.multipart.fileField, spec.multipart.filename))
		header.Set("Content-Type", img.MimeType)
		part, err := writer.CreatePart(header)
		if err != nil {
			return nil, fmt.Errorf("rest: create multipart file part: %w", err)
		}
		if _, err := part.Write(data); err != nil {
			return nil, fmt.Errorf("rest: write multipart file part: %w", err)
		}
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("rest: close multipart writer: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, spec.method, spec.uri, &buf)
	if err != nil {
		return nil, fmt.Errorf("rest: failed to create request: %w", err)
	}

	r.applyHeaders(req, spec.headers, prompt, hookVars)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req, nil
}
```

- [ ] **Step 5: Update `applyHeaders` to take a headers map**

Replace `applyHeaders` (L617-621) with:

```go
// applyHeaders sets the given headers on req, substituting templates.
func (r *Rest) applyHeaders(req *http.Request, headers map[string]string, prompt string, hookVars map[string]string) {
	for k, v := range headers {
		req.Header.Set(k, r.populateTemplate(v, prompt, hookVars))
	}
}
```

- [ ] **Step 6: Update the single `buildRequest` call site in `callAPI`**

In `callAPI` (around L387), change:

```go
	req, err := r.buildRequest(ctx, conv, prompt, hookVars, img)
```

to:

```go
	req, err := r.buildRequest(ctx, r.mainSpec(), conv, prompt, hookVars, img)
```

- [ ] **Step 7: Build and run the full existing suite as the regression guard**

Run: `go build ./... && go test ./internal/generators/rest/ -race`
Expected: PASS (all existing tests, including `TestRestGenerator_Vision_*`, still green — this task changed no behavior).

- [ ] **Step 8: Format and commit**

```bash
golangci-lint fmt ./... 2>/dev/null || gofmt -w internal/generators/rest/rest.go
git add internal/generators/rest/rest.go
git commit -m "refactor: thread requestSpec through REST request builders

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Add `uploadConfig` type, parsing, and validation

Extract the body_mode/multipart parsing into a shared `parseImageTransport` helper (so the upload block reuses it DRY-ly), add the `uploadConfig` struct and the `upload *uploadConfig` field on `Rest`, and parse+validate the `upload` config block in `NewRest`. No request is sent yet — this task is config surface + validation only.

**Files:**
- Modify: `internal/generators/rest/rest.go` (`Rest` struct L93-126; `configureImageTransport` L1048-1097; `NewRest` around L318)
- Test: `internal/generators/rest/rest_test.go`

**Interfaces:**
- Consumes: `requestSpec`, `multipartConfig`, `bodyModeRawBinary` (Task 1 / existing).
- Produces:
  - `func parseImageTransport(m map[string]any) (bodyMode string, mp *multipartConfig, err error)`
  - `type uploadConfig struct { uri, method string; headers map[string]string; reqTemplate, bodyMode string; multipart *multipartConfig; capture map[string]string }`
  - `func (u *uploadConfig) toRequestSpec() requestSpec`
  - `func (u *uploadConfig) carriesImage() bool`
  - `func (r *Rest) configureUpload(cfg registry.Config) error`
  - New field on `Rest`: `upload *uploadConfig`
  - `capture` values are `header:` prefixed for a header capture, otherwise a JSONPath (`$...`).

- [ ] **Step 1: Write failing validation tests**

Add to `rest_test.go`:

```go
func TestNewRest_Upload_Validation(t *testing.T) {
	t.Run("upload requires uri", func(t *testing.T) {
		_, err := NewRest(registry.Config{
			"uri": "http://example.invalid",
			"upload": map[string]any{
				"body_mode": "raw_binary",
				"capture":   map[string]any{"FILE_ID": "$.id"},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "upload")
		assert.Contains(t, err.Error(), "uri")
	})

	t.Run("upload requires an image transport mode", func(t *testing.T) {
		_, err := NewRest(registry.Config{
			"uri": "http://example.invalid",
			"upload": map[string]any{
				"uri":     "http://upload.invalid",
				"capture": map[string]any{"FILE_ID": "$.id"},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "image")
	})

	t.Run("upload capture key must be uppercase alnum", func(t *testing.T) {
		_, err := NewRest(registry.Config{
			"uri": "http://example.invalid",
			"upload": map[string]any{
				"uri":       "http://upload.invalid",
				"body_mode": "raw_binary",
				"capture":   map[string]any{"file-id": "$.id"},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "capture")
	})

	t.Run("upload raw_binary and multipart are mutually exclusive", func(t *testing.T) {
		_, err := NewRest(registry.Config{
			"uri": "http://example.invalid",
			"upload": map[string]any{
				"uri":       "http://upload.invalid",
				"body_mode": "raw_binary",
				"multipart": map[string]any{"file_field": "file"},
				"capture":   map[string]any{"FILE_ID": "$.id"},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mutually exclusive")
	})

	t.Run("valid upload config parses", func(t *testing.T) {
		g, err := NewRest(registry.Config{
			"uri": "http://example.invalid/analyze/$FILE_ID",
			"upload": map[string]any{
				"uri":       "http://upload.invalid",
				"body_mode": "raw_binary",
				"capture":   map[string]any{"FILE_ID": "$.id"},
			},
		})
		require.NoError(t, err)
		r := g.(*Rest)
		require.NotNil(t, r.upload)
		assert.Equal(t, "http://upload.invalid", r.upload.uri)
		assert.True(t, r.upload.carriesImage())
		assert.Equal(t, "$.id", r.upload.capture["FILE_ID"])
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/generators/rest/ -run TestNewRest_Upload_Validation -v`
Expected: FAIL / compile error (`r.upload` undefined, `configureUpload` undefined).

- [ ] **Step 3: Add the `upload` field to the `Rest` struct**

In the `Rest` struct, right after the multimodal image-transport fields (after L121 `multipart *multipartConfig`), add:

```go
	// Two-step upload flow: when set, an upload pre-request runs before the main
	// request, capturing values substituted into it via $VAR placeholders.
	upload *uploadConfig
```

- [ ] **Step 4: Extract `parseImageTransport` and simplify `configureImageTransport`**

Replace `configureImageTransport` (L1048-1097) with:

```go
// parseImageTransport reads the optional body_mode and multipart settings from a
// config sub-map and returns the resulting transport. body_mode raw_binary and
// multipart are mutually exclusive. Used for both the top-level request and the
// upload pre-request.
func parseImageTransport(m map[string]any) (string, *multipartConfig, error) {
	var bodyMode string
	if mode, ok := m["body_mode"].(string); ok && mode != "" {
		if mode != bodyModeRawBinary {
			return "", nil, fmt.Errorf("rest: invalid body_mode %q (only %q is supported)", mode, bodyModeRawBinary)
		}
		bodyMode = mode
	}

	raw, ok := m["multipart"]
	if !ok {
		return bodyMode, nil, nil
	}
	mpRaw, ok := raw.(map[string]any)
	if !ok {
		return "", nil, fmt.Errorf("rest: multipart must be an object")
	}
	if bodyMode == bodyModeRawBinary {
		return "", nil, fmt.Errorf("rest: body_mode %q and multipart are mutually exclusive", bodyModeRawBinary)
	}

	fileField, _ := mpRaw["file_field"].(string)
	if fileField == "" {
		return "", nil, fmt.Errorf("rest: multipart requires a non-empty file_field")
	}

	filename := "image.png"
	if fn, ok := mpRaw["filename"].(string); ok && fn != "" {
		filename = fn
	}

	fields := make(map[string]string)
	if rawFields, ok := mpRaw["fields"].(map[string]any); ok {
		for k, v := range rawFields {
			if vs, ok := v.(string); ok {
				fields[k] = vs
			}
		}
	}

	return bodyMode, &multipartConfig{fileField: fileField, filename: filename, fields: fields}, nil
}

// configureImageTransport parses the top-level body_mode and multipart settings
// that control how a probe's image is placed on the wire.
func (r *Rest) configureImageTransport(cfg registry.Config) error {
	bodyMode, mp, err := parseImageTransport(cfg)
	if err != nil {
		return err
	}
	r.bodyMode = bodyMode
	r.multipart = mp
	return nil
}
```

- [ ] **Step 5: Add the `uploadConfig` type and `configureUpload`**

Append to `rest.go`:

```go
// uploadConfig describes the pre-request "upload" step of a two-step multimodal
// flow: it sends the probe's image to an upload endpoint and captures named
// values from the response for substitution into the main ("analyze") request.
type uploadConfig struct {
	uri         string
	method      string
	headers     map[string]string
	reqTemplate string
	bodyMode    string
	multipart   *multipartConfig
	// capture maps a variable name (^[A-Z0-9_]+$) to a source: a JSONPath into
	// the response body ("$.data.id"), or "header:Name" for a response header.
	capture map[string]string
}

// toRequestSpec adapts the upload config to the shared requestSpec used by the
// request builders.
func (u *uploadConfig) toRequestSpec() requestSpec {
	return requestSpec{
		uri:         u.uri,
		method:      u.method,
		headers:     u.headers,
		reqTemplate: u.reqTemplate,
		bodyMode:    u.bodyMode,
		multipart:   u.multipart,
	}
}

// carriesImage reports whether the upload step is configured with somewhere for
// the image to go (raw-binary body, multipart file part, or an $IMAGE_ template).
func (u *uploadConfig) carriesImage() bool {
	return u.bodyMode == bodyModeRawBinary ||
		u.multipart != nil ||
		strings.Contains(u.reqTemplate, "$IMAGE_")
}

// configureUpload parses and validates the optional "upload" config block.
func (r *Rest) configureUpload(cfg registry.Config) error {
	raw, ok := cfg["upload"]
	if !ok {
		return nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("rest: upload must be an object")
	}

	u := &uploadConfig{
		method:  "POST",
		headers: make(map[string]string),
		capture: make(map[string]string),
	}

	uri, _ := m["uri"].(string)
	if uri == "" {
		return fmt.Errorf("rest: upload requires a non-empty uri")
	}
	u.uri = uri

	if method, ok := m["method"].(string); ok && method != "" {
		u.method = strings.ToUpper(method)
	}

	if headers, ok := m["headers"].(map[string]any); ok {
		for k, v := range headers {
			if vs, ok := v.(string); ok {
				u.headers[k] = vs
			}
		}
	}

	if tmpl, ok := m["req_template"].(string); ok {
		u.reqTemplate = tmpl
	}

	bodyMode, mp, err := parseImageTransport(m)
	if err != nil {
		return err
	}
	u.bodyMode = bodyMode
	u.multipart = mp

	if !u.carriesImage() {
		return fmt.Errorf("rest: upload requires an image transport mode " +
			"(body_mode raw_binary, multipart, or a req_template containing $IMAGE_)")
	}

	if rawCapture, ok := m["capture"].(map[string]any); ok {
		for k, v := range rawCapture {
			vs, ok := v.(string)
			if !ok {
				return fmt.Errorf("rest: upload capture %q must be a string", k)
			}
			if !validKeyPattern.MatchString(k) {
				return fmt.Errorf("rest: upload capture key %q must match ^[A-Z0-9_]+$", k)
			}
			u.capture[k] = vs
		}
	}

	r.upload = u
	return nil
}
```

Note: `validKeyPattern` lives in `pkg/hooks/hooks.go` (unexported). Add a package-local copy in `rest.go` near the top-level vars (it is not exported from `hooks`):

```go
// validCaptureKey restricts upload capture variable names to uppercase
// alphanumeric and underscores, matching the runtime hook-var key rule.
var validCaptureKey = regexp.MustCompile(`^[A-Z0-9_]+$`)
```

Then use `validCaptureKey` (not `validKeyPattern`) in `configureUpload`, and add `"regexp"` to the import block.

- [ ] **Step 6: Call `configureUpload` from `NewRest`**

In `NewRest`, right after the `configureImageTransport` call (L317-320), add:

```go
	// Optional: two-step upload flow.
	if err := r.configureUpload(cfg); err != nil {
		return nil, err
	}
```

- [ ] **Step 7: Run the validation tests**

Run: `go test ./internal/generators/rest/ -run TestNewRest_Upload_Validation -v`
Expected: PASS (all five subtests).

- [ ] **Step 8: Build, run full suite, format, commit**

```bash
go build ./... && go test ./internal/generators/rest/ -race
golangci-lint fmt ./... 2>/dev/null || gofmt -w internal/generators/rest/rest.go internal/generators/rest/rest_test.go
git add internal/generators/rest/rest.go internal/generators/rest/rest_test.go
git commit -m "feat: parse and validate REST upload config block (LAB-4174)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Implement capture parsing (`parseCapture`)

Given an upload HTTP response and its already-read body, apply the `capture` rules and return a `map[string]string` of variable name → captured value. Body captures use the existing `parseResponse`/`extractField` JSON machinery; header captures use `resp.Header.Get`. A declared capture that resolves to nothing (JSON path missing, or empty header) is an error (fail-loud).

**Files:**
- Modify: `internal/generators/rest/rest.go`
- Test: `internal/generators/rest/rest_test.go`

**Interfaces:**
- Consumes: `uploadConfig.capture`, existing `r.extractField` (L718), `attempt`/`http` types.
- Produces: `func (r *Rest) parseCapture(resp *http.Response, body []byte) (map[string]string, error)`
- Header capture source format: `header:Name` (case-insensitive header lookup via `http.Header.Get`). Any other value is treated as a JSONPath/field passed to `extractField`.

- [ ] **Step 1: Write failing tests for `parseCapture`**

Add to `rest_test.go`:

```go
func TestRest_parseCapture(t *testing.T) {
	r := &Rest{
		upload: &uploadConfig{
			capture: map[string]string{
				"FILE_ID":    "$.data.id",
				"UPLOAD_URL": "header:Location",
			},
		},
	}

	t.Run("captures body JSONPath and response header", func(t *testing.T) {
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Set("Location", "https://cdn.example/obj/42")
		body := []byte(`{"data":{"id":"abc123"}}`)

		got, err := r.parseCapture(resp, body)
		require.NoError(t, err)
		assert.Equal(t, "abc123", got["FILE_ID"])
		assert.Equal(t, "https://cdn.example/obj/42", got["UPLOAD_URL"])
	})

	t.Run("missing body path errors", func(t *testing.T) {
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Set("Location", "https://cdn.example/obj/42")
		body := []byte(`{"data":{}}`)

		_, err := r.parseCapture(resp, body)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "FILE_ID")
	})

	t.Run("missing header errors", func(t *testing.T) {
		resp := &http.Response{Header: http.Header{}}
		body := []byte(`{"data":{"id":"abc123"}}`)

		_, err := r.parseCapture(resp, body)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "UPLOAD_URL")
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/generators/rest/ -run TestRest_parseCapture -v`
Expected: FAIL (`parseCapture` undefined).

- [ ] **Step 3: Implement `parseCapture`**

Append to `rest.go`:

```go
// captureHeaderPrefix marks a capture source that reads a response header
// ("header:Location") rather than a JSONPath into the response body.
const captureHeaderPrefix = "header:"

// parseCapture applies the upload step's capture rules to the upload response,
// returning variable name -> captured value. Body captures use the JSON field /
// JSONPath engine; "header:Name" captures read a response header. A declared
// capture that resolves to an empty value is an error (fail-loud: never let the
// main request proceed with a missing handle).
func (r *Rest) parseCapture(resp *http.Response, body []byte) (map[string]string, error) {
	out := make(map[string]string, len(r.upload.capture))

	// Decode the body once, only if a body capture is present.
	var decoded any
	var decodedErr error
	var decodedOnce bool
	ensureDecoded := func() error {
		if !decodedOnce {
			decodedOnce = true
			decodedErr = json.Unmarshal(body, &decoded)
		}
		return decodedErr
	}

	for name, source := range r.upload.capture {
		if strings.HasPrefix(source, captureHeaderPrefix) {
			headerName := strings.TrimPrefix(source, captureHeaderPrefix)
			val := resp.Header.Get(headerName)
			if val == "" {
				return nil, fmt.Errorf("rest: upload capture %q: response header %q is empty or absent", name, headerName)
			}
			out[name] = val
			continue
		}

		if err := ensureDecoded(); err != nil {
			return nil, fmt.Errorf("rest: upload capture %q: parse response JSON: %w", name, err)
		}
		val, err := r.extractField(decoded, source)
		if err != nil {
			return nil, fmt.Errorf("rest: upload capture %q: %w", name, err)
		}
		if val == "" {
			return nil, fmt.Errorf("rest: upload capture %q resolved to an empty value at %q", name, source)
		}
		out[name] = val
	}

	return out, nil
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/generators/rest/ -run TestRest_parseCapture -v`
Expected: PASS (all three subtests).

- [ ] **Step 5: Build, format, commit**

```bash
go build ./... && go test ./internal/generators/rest/ -race
golangci-lint fmt ./... 2>/dev/null || gofmt -w internal/generators/rest/rest.go internal/generators/rest/rest_test.go
git add internal/generators/rest/rest.go internal/generators/rest/rest_test.go
git commit -m "feat: capture values from REST upload response (LAB-4174)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Wire the upload pre-request into `callAPI` + extend `SupportsVision`

Add `doUpload`, call it from `callAPI` when `r.upload != nil`, merge captured vars into `hookVars`, send the main request with the image omitted, and extend `SupportsVision` to account for the upload step. This is the integration task with end-to-end `httptest` coverage.

**Files:**
- Modify: `internal/generators/rest/rest.go` (`callAPI` L365-455; `SupportsVision` L1042-1046)
- Test: `internal/generators/rest/rest_test.go`

**Interfaces:**
- Consumes: `r.upload`, `uploadConfig.toRequestSpec`/`carriesImage`, `r.buildRequest`, `r.parseCapture`, `r.mainSpec` (Tasks 1-3).
- Produces: `func (r *Rest) doUpload(ctx context.Context, conv *attempt.Conversation, prompt string, hookVars map[string]string, img *attempt.Image) (map[string]string, error)`

- [ ] **Step 1: Write failing end-to-end tests**

Add to `rest_test.go`:

```go
func TestRestGenerator_Upload_TwoStep_HappyPath(t *testing.T) {
	var uploadBody []byte
	var uploadCT string
	var analyzePath string
	var analyzeBody map[string]string

	uploadSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploadCT = r.Header.Get("Content-Type")
		uploadBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"file-42"}}`))
	}))
	defer uploadSrv.Close()

	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		analyzePath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &analyzeBody)
		_, _ = w.Write([]byte(`{"text":"a cat"}`))
	}))
	defer analyzeSrv.Close()

	g, err := NewRest(registry.Config{
		"uri":                 analyzeSrv.URL + "/analyze/$FILE_ID",
		"req_template":        `{"file":"$FILE_ID","prompt":"$INPUT"}`,
		"response_json":       true,
		"response_json_field": "$.text",
		"upload": map[string]any{
			"uri":       uploadSrv.URL,
			"body_mode": "raw_binary",
			"capture":   map[string]any{"FILE_ID": "$.data.id"},
		},
	})
	require.NoError(t, err)

	conv := convWithImage("describe this", "image/png", smallPNG)
	msgs, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	require.Len(t, msgs, 1)

	// Upload received the raw image.
	assert.Equal(t, smallPNG, uploadBody)
	assert.Equal(t, "image/png", uploadCT)
	// Analyze received the captured handle in both URL and body, plus the prompt.
	assert.Equal(t, "/analyze/file-42", analyzePath)
	assert.Equal(t, "file-42", analyzeBody["file"])
	assert.Equal(t, "describe this", analyzeBody["prompt"])
	// And the analyze response was parsed.
	assert.Equal(t, "a cat", msgs[0].Content)
}

func TestRestGenerator_Upload_CaptureFromHeader(t *testing.T) {
	var analyzeHeader string
	uploadSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://cdn.example/obj/99")
		w.WriteHeader(http.StatusCreated)
	}))
	defer uploadSrv.Close()

	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		analyzeHeader = r.Header.Get("X-Upload-Url")
		_, _ = w.Write([]byte("ok"))
	}))
	defer analyzeSrv.Close()

	g, err := NewRest(registry.Config{
		"uri":          analyzeSrv.URL,
		"req_template": `{"prompt":"$INPUT"}`,
		"headers":      map[string]any{"X-Upload-Url": "$UPLOAD_URL"},
		"upload": map[string]any{
			"uri":       uploadSrv.URL,
			"body_mode": "raw_binary",
			"capture":   map[string]any{"UPLOAD_URL": "header:Location"},
		},
	})
	require.NoError(t, err)

	conv := convWithImage("hi", "image/png", smallPNG)
	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	assert.Equal(t, "https://cdn.example/obj/99", analyzeHeader)
}

func TestRestGenerator_Upload_MultipartStep(t *testing.T) {
	var gotField string
	var gotBytes []byte
	uploadSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseMultipartForm(10<<20))
		for name, files := range r.MultipartForm.File {
			gotField = name
			f, _ := files[0].Open()
			defer func() { _ = f.Close() }()
			gotBytes, _ = io.ReadAll(f)
		}
		_, _ = w.Write([]byte(`{"id":"m1"}`))
	}))
	defer uploadSrv.Close()

	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer analyzeSrv.Close()

	g, err := NewRest(registry.Config{
		"uri":          analyzeSrv.URL,
		"req_template": `{"file":"$FILE_ID"}`,
		"upload": map[string]any{
			"uri":       uploadSrv.URL,
			"multipart": map[string]any{"file_field": "upload", "filename": "x.png"},
			"capture":   map[string]any{"FILE_ID": "$.id"},
		},
	})
	require.NoError(t, err)

	conv := convWithImage("classify", "image/png", smallPNG)
	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	assert.Equal(t, "upload", gotField)
	assert.Equal(t, smallPNG, gotBytes)
}

func TestRestGenerator_Upload_NoImageErrors(t *testing.T) {
	g, err := NewRest(registry.Config{
		"uri": "http://analyze.invalid",
		"upload": map[string]any{
			"uri":       "http://upload.invalid",
			"body_mode": "raw_binary",
			"capture":   map[string]any{"FILE_ID": "$.id"},
		},
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("no image")
	_, err = g.Generate(context.Background(), conv, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "upload")
	assert.Contains(t, err.Error(), "image")
}

func TestRestGenerator_Upload_UploadFailurePropagates(t *testing.T) {
	uploadSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer uploadSrv.Close()

	g, err := NewRest(registry.Config{
		"uri":          "http://analyze.invalid",
		"req_template": `{"file":"$FILE_ID"}`,
		"upload": map[string]any{
			"uri":       uploadSrv.URL,
			"body_mode": "raw_binary",
			"capture":   map[string]any{"FILE_ID": "$.id"},
		},
	})
	require.NoError(t, err)

	conv := convWithImage("hi", "image/png", smallPNG)
	_, err = g.Generate(context.Background(), conv, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "upload")
}

func TestRestGenerator_SupportsVision_Upload(t *testing.T) {
	g, err := NewRest(registry.Config{
		"uri":          "http://analyze.invalid",
		"req_template": `{"file":"$FILE_ID"}`, // main request has NO $IMAGE_
		"upload": map[string]any{
			"uri":       "http://upload.invalid",
			"body_mode": "raw_binary",
			"capture":   map[string]any{"FILE_ID": "$.id"},
		},
	})
	require.NoError(t, err)
	assert.True(t, g.(*Rest).SupportsVision())
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/generators/rest/ -run 'TestRestGenerator_Upload|TestRestGenerator_SupportsVision_Upload' -v`
Expected: FAIL (`doUpload` not wired; captured vars not substituted; `SupportsVision` doesn't see upload).

- [ ] **Step 3: Implement `doUpload`**

Append to `rest.go`:

```go
// doUpload runs the two-step flow's pre-request: it sends the probe's image to
// the upload endpoint and returns the captured variables. Any non-2xx status or
// an unresolved capture is an error, so the main request never proceeds with a
// missing handle.
func (r *Rest) doUpload(
	ctx context.Context,
	conv *attempt.Conversation,
	prompt string,
	hookVars map[string]string,
	img *attempt.Image,
) (map[string]string, error) {
	if img == nil {
		return nil, fmt.Errorf("rest: upload flow requires an image attachment")
	}

	req, err := r.buildRequest(ctx, r.upload.toRequestSpec(), conv, prompt, hookVars, img)
	if err != nil {
		return nil, fmt.Errorf("rest: build upload request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rest: upload request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("rest: upload returned non-2xx status: %d %s", resp.StatusCode, resp.Status)
	}

	const maxResponseSize = 10 * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("rest: read upload response: %w", err)
	}

	return r.parseCapture(resp, body)
}
```

- [ ] **Step 4: Wire `doUpload` into `callAPI`**

In `callAPI`, replace the image-selection + build block (currently L378-390):

```go
	// The first image on the last prompt (if any) is the probe-injected image.
	// Image data never enters config — Augustus attaches it at run time.
	var img *attempt.Image
	if pm := conv.LastPromptMessage(); pm != nil && len(pm.Images) > 0 {
		img = &pm.Images[0]
	}

	// Build the HTTP request body and content type according to the configured
	// wire mode (raw binary, multipart, or JSON template).
	req, err := r.buildRequest(ctx, r.mainSpec(), conv, prompt, hookVars, img)
	if err != nil {
		return attempt.Message{}, err
	}
```

with:

```go
	// The first image on the last prompt (if any) is the probe-injected image.
	// Image data never enters config — Augustus attaches it at run time.
	var img *attempt.Image
	if pm := conv.LastPromptMessage(); pm != nil && len(pm.Images) > 0 {
		img = &pm.Images[0]
	}

	// Two-step flow: upload the image first, capture handle(s) into the var map,
	// then send the main request with the image omitted (it was consumed above).
	if r.upload != nil {
		captured, err := r.doUpload(ctx, conv, prompt, hookVars, img)
		if err != nil {
			return attempt.Message{}, err
		}
		merged := make(map[string]string, len(hookVars)+len(captured))
		for k, v := range hookVars {
			merged[k] = v
		}
		for k, v := range captured {
			merged[k] = v // captured values win on key collision
		}
		hookVars = merged
		img = nil
	}

	// Build the HTTP request body and content type according to the configured
	// wire mode (raw binary, multipart, or JSON template).
	req, err := r.buildRequest(ctx, r.mainSpec(), conv, prompt, hookVars, img)
	if err != nil {
		return attempt.Message{}, err
	}
```

- [ ] **Step 5: Extend `SupportsVision`**

Replace `SupportsVision` (L1042-1046) with:

```go
func (r *Rest) SupportsVision() bool {
	if r.upload != nil && r.upload.carriesImage() {
		return true
	}
	return r.bodyMode == bodyModeRawBinary ||
		r.multipart != nil ||
		strings.Contains(r.reqTemplate, "$IMAGE_")
}
```

- [ ] **Step 6: Run the new integration tests**

Run: `go test ./internal/generators/rest/ -run 'TestRestGenerator_Upload|TestRestGenerator_SupportsVision_Upload' -v`
Expected: PASS (all subtests).

- [ ] **Step 7: Build, run full suite with race, format, commit**

```bash
go build ./... && go test ./internal/generators/rest/ -race
golangci-lint fmt ./... 2>/dev/null || gofmt -w internal/generators/rest/rest.go internal/generators/rest/rest_test.go
git add internal/generators/rest/rest.go internal/generators/rest/rest_test.go
git commit -m "feat: wire REST two-step image-upload flow into callAPI (LAB-4174)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Final verification

**Files:** none (verification only).

- [ ] **Step 1: Full module build + vet**

Run: `go build ./... && go vet ./internal/generators/rest/`
Expected: no output / exit 0.

- [ ] **Step 2: Full test suite with race across the module**

Run: `make test` (or `go test ./... -race` if `make` is unavailable)
Expected: PASS.

- [ ] **Step 3: Lint gate matches CI**

Run: `make lint` (or `golangci-lint run ./internal/generators/rest/`)
Expected: no findings. If `golangci-lint` is unavailable, run `gofmt -l internal/generators/rest/` and confirm it prints nothing.

- [ ] **Step 4: Confirm no stray uncommitted changes**

Run: `git status --porcelain`
Expected: empty (everything committed across Tasks 1-4).

---

## Self-Review

**Spec coverage:**
- Config schema (`upload` block: uri/method/headers/body_mode/multipart/req_template/response_json/capture) → Task 2.
- Data flow steps 1-6 (detect upload, build via shared builders, capture, merge, image-omitted main, URI templating) → Task 1 (spec/URI templating) + Task 4 (wiring).
- `SupportsVision` upload check → Task 4 Step 5.
- Escaping (reuse `populateTemplate`) → Task 1 (URI) + inherent in existing template path.
- Errors: upload non-2xx → Task 4 `doUpload`; capture-miss → Task 3 `parseCapture`; no-image → Task 4 `doUpload`.
- Validation (upload uri, image mode required, capture key pattern, raw_binary/multipart exclusivity, body capture forces JSON) → Task 2. Note: body-JSONPath capture doesn't require an explicit `response_json` flag because `parseCapture` unmarshals the body directly for JSONPath sources — the spec's "forces `response_json`" intent is satisfied structurally (JSON is always parsed for a body capture), so no separate flag toggle is needed.
- Raw-response hook returns main response → unchanged (Task 4 leaves `r.lastRawResp` written only in `callAPI` after the main request).
- Testing items 1-9 → Tasks 2-4 test steps.

**Placeholder scan:** No TBD/TODO/"handle edge cases"; every code step shows complete code.

**Type consistency:** `requestSpec` fields and `buildRequest`/`buildTemplateRequest`/`buildRawBinaryRequest`/`buildMultipartRequest`/`applyHeaders` signatures are consistent between Task 1 (definition) and Task 4 (use). `uploadConfig` fields, `toRequestSpec`, `carriesImage`, `parseCapture`, and `doUpload` signatures are consistent between Tasks 2-4. `capture` source format (`header:` prefix vs JSONPath) is consistent between Task 2 (parse), Task 3 (`parseCapture`), and Task 4 (tests).

**One correction folded in:** the spec mentioned "body-JSONPath capture forces `response_json` on the upload step." In implementation, `parseCapture` unmarshals the upload body on demand for any JSONPath source, so there is no separate `response_json` toggle on the upload block — parsing is unconditional for body captures. This is noted above and is behavior-equivalent to the spec's intent (a body capture always parses JSON).
