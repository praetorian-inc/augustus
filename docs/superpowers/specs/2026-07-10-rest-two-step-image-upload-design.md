# REST multimodal: two-step / multi-request image-upload flows

**Ticket:** LAB-4174
**Date:** 2026-07-10
**Status:** Approved design

## Problem

PR #104 added single-request multimodal image transport to the generic `rest.Rest`
generator via three wire modes:

- **A.** base64 in a JSON body (`$IMAGE_B64` / `$IMAGE_DATAURI` / `$IMAGE_MIME` placeholders)
- **B.** `multipart/form-data` (`multipart: {file_field, filename, fields}`)
- **C.** raw binary body (`body_mode: raw_binary`)

Out of scope then, tracked here: **two-step upload flows** where an upload request
returns an ID/handle (or a URL) and a separate "analyze this" call references it —
presigned-URL / object-store ingestion, async OCR pipelines, etc. These need
multi-request orchestration: chain a request, capture a value from its response,
substitute it into a follow-up request.

Today the closest mechanism is the runtime-hook variable system
(`pkg/hooks`): a `HookedGenerator` runs a shell command before each `Generate`,
parses `KEY=VALUE` from stdout, and injects `$KEY` substitutions into the request
template. That is shell-based and external. This feature brings the same
capture-and-substitute idea *natively inside* the REST generator, over HTTP, with
no shell scripts required.

## Design

Add an optional `upload` block to the `rest.Rest` config. When present and an image
is attached, `Generate` performs a pre-request (the upload) before the existing main
request: it sends the image to the upload endpoint, captures named values from the
upload response, and substitutes them into the main "analyze" request's URL, body,
and headers.

### Config schema

```yaml
upload:
  uri: https://api.example.com/v1/files       # required
  method: POST                                 # default POST
  headers: { Authorization: "Bearer $KEY" }    # optional; supports $KEY / hook vars
  # image transport for the upload step — same three modes as the main request:
  body_mode: raw_binary                         # OR
  multipart: { file_field: file, filename: img.png, fields: {...} }   # OR
  req_template: '{"image":"$IMAGE_B64"}'        # JSON template with $IMAGE_ placeholders
  response_json: true                           # for JSONPath capture (auto-on if any body capture)
  capture:
    FILE_ID:    $.data.id           # JSONPath into upload response body
    UPLOAD_URL: header:Location     # response header (case-insensitive)

# main ("analyze") request — existing config, now able to reference captured vars:
uri: https://api.example.com/v1/analyze/$FILE_ID
req_template: '{"file":"$FILE_ID","prompt":"$INPUT"}'
headers:
  X-Upload-Url: $UPLOAD_URL
response_json: true
response_json_field: $.result.text
```

The main request keeps its existing config and gains the captured vars for
substitution. `upload` is entirely optional; absent it, behavior is unchanged.

### Data flow (per `Generate` call)

1. `callAPI` detects `r.upload != nil` and an attached image → runs
   `doUpload(ctx, img, hookVars)`.
2. `doUpload` builds the upload request using the **same** `buildRequest` dispatch
   (raw-binary / multipart / template) that already exists — reused, not duplicated —
   configured from the upload step and with the image attached.
3. On a 2xx response, it evaluates `capture`:
   - JSONPath entries (starting with `$`) run through the existing `extractField`.
   - `header:Name` entries read `resp.Header.Get(Name)`.
   Results become a `map[string]string`.
4. Captured vars are **merged into the hookVars map** (captured values win on key
   collision) and passed to the main request.
5. The main request builds as today, but with the image **omitted** (`img = nil`) —
   the image was consumed by the upload — so `$IMAGE_` placeholders are not expected
   there, and captured `$FILE_ID` / `$UPLOAD_URL` substitute via the existing
   `populateTemplate`.
6. **URI templating (new):** the main `uri` is run through `populateTemplate` so
   `/analyze/$FILE_ID` works. The upload `uri` is likewise templated so it can
   reference existing hook/setup vars.

### Key details

- **`SupportsVision()`**: returns true when the upload step is configured to carry an
  image (its `body_mode` / `multipart` / `$IMAGE_` template), in addition to the
  existing main-request checks. A two-step target thus honestly reports vision support
  instead of silently dropping the image.
- **Escaping**: captured values reuse `populateTemplate`'s JSON-escaping (keeps JSON
  bodies valid). For typical handles/IDs and URLs this is a no-op. Known limitation:
  exotic values (containing quotes/backslashes) substituted into a URL path are
  JSON-escaped rather than URL-escaped; acceptable for the handle/URL shapes these
  APIs return.
- **Errors (fail loud, never silently analyze with an empty handle):**
  - Upload non-2xx → `Generate` returns an error.
  - A declared capture (JSONPath or header) that resolves to nothing → error.
  - Any non-2xx upload status → error. Skip/rate-limit codes are not specially
    handled for the upload step: a skipped or rate-limited upload cannot yield a
    handle, so proceeding would violate fail-loud.
  - `upload` configured but no image attached on the prompt → error (the two-step
    flow requires an image to upload).
- **Validation (`NewRest`)**:
  - `upload` requires a non-empty `uri`.
  - `upload` requires at least one image transport mode (`body_mode: raw_binary`,
    `multipart`, or a `req_template` containing `$IMAGE_`).
  - `body_mode: raw_binary` and `multipart` remain mutually exclusive within the
    upload step (same rule as the main request).
  - `capture` keys must match `^[A-Z0-9_]+$` (same pattern as hook vars).
  - `capture` values are either a JSONPath (`$...`) or `header:Name`.
  - Any body-JSONPath capture forces `response_json` on the upload step.
- **Raw-response hook**: `LastRawResponse()` continues to return the **main**
  (analyze) response, unchanged, so runtime hooks and `RawResponseProvider` consumers
  see the analyze response as before.

### Structure / units

- `uploadConfig` struct: holds the upload step's uri, method, headers, image-transport
  fields (mirrors the relevant `Rest` fields), and the parsed `capture` map.
- `configureUpload(cfg) (*uploadConfig, error)`: parses and validates the `upload`
  block in `NewRest` (parallels the existing `configureImageTransport`).
- `doUpload(ctx, img, hookVars) (map[string]string, error)`: runs the upload request
  and returns captured vars. Reuses `buildRequest` and `extractField`.
- `parseCapture(resp, body) (map[string]string, error)`: applies the capture rules to
  the upload response body + headers.
- `callAPI` gains the pre-request branch and URI templating; `SupportsVision` gains
  the upload-step check.

## Testing

Table-driven tests using `httptest.Server`:

1. upload → capture body value → analyze happy path.
2. capture from a `Location` response header.
3. each image mode on the upload step (raw_binary, multipart, `$IMAGE_B64` template).
4. `$FILE_ID` substituted into the main request URI path.
5. upload failure (non-2xx) propagates as an error.
6. capture-miss (declared JSONPath/header absent) errors.
7. `SupportsVision` true when upload carries the image; false without upload and
   without main-request image transport.
8. config validation errors (missing upload uri, no image mode, bad capture key,
   raw_binary + multipart together).
9. `upload` configured but no image attached → error.

## Out of scope

- General N-step chains (upload → poll → analyze). If a future need arises, the
  single-step design can be generalized to a `requests: [...]` list; not built now
  (YAGNI).
- Non-image payloads in the upload step (documents/PDFs); this ticket is scoped to
  image flows, consistent with PR #104.
