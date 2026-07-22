package attempt

// Metadata key constants used across probes, buffs, and detectors.
// Using these constants prevents silent breakage from key typos.
const (
	MetadataKeySystemPrompt = "system_prompt"
	MetadataKeyTriggers     = "triggers"
	MetadataKeyFlipMode     = "flip_mode"
	MetadataKeyVariant      = "variant"
	MetadataKeyToolCalls    = "tool_calls"

	// MetadataKeyGoal carries the probe's objective so goal-conditioned
	// detectors (e.g. agent.ToolLeakJudge) can read it from the attempt. The
	// multi-turn / PAIR-TAP attack engines already write this key; surfacing it
	// for single-turn template probes lets judge detectors work in chat-mode.
	MetadataKeyGoal = "goal"

	// MetadataKeyInjectionCanaries holds the []string of canary markers a
	// mcptool injection probe expects to see in a tool's output if the tool
	// evaluated the injected payload. Read by the mcptool.Injection detector.
	MetadataKeyInjectionCanaries = "mcptool.injection_canaries"

	// MetadataKeySSRFCallback (bool) records whether the mcptool.SSRF probe's
	// out-of-band collector received a callback for this attempt's canary URL —
	// proof of server-side request forgery, including the blind case.
	MetadataKeySSRFCallback = "mcptool.ssrf_callback"
	// MetadataKeySSRFReflected (bool) records whether the tool's response
	// contained the collector's body marker (non-blind SSRF: the tool fetched
	// the URL and returned its content).
	MetadataKeySSRFReflected = "mcptool.ssrf_reflected"
	// MetadataKeySSRFOOBURL (string) is the canary URL injected for this attempt.
	MetadataKeySSRFOOBURL = "mcptool.ssrf_oob_url"

	// MetadataKeyBOLAID (string) is the victim object identifier the mcptool.BOLA
	// probe called a getter with under the attacker's identity.
	MetadataKeyBOLAID = "mcptool.bola.id"
	// MetadataKeyBOLAVictimIdentity (string) labels the identity that owns the
	// object the attacker attempted to read.
	MetadataKeyBOLAVictimIdentity = "mcptool.bola.victim_identity"
	// MetadataKeyBOLAPositiveControl (string) is the attacker's OWN-object response
	// for the same getter — a served baseline the mcptool.BOLA detector's judge uses
	// to calibrate what "served" looks like on this server. Absent when the attacker
	// owns no object for that getter.
	MetadataKeyBOLAPositiveControl = "mcptool.bola.positive_control"
	// MetadataKeyBOLANegativeControl (string) is the attacker's response for a
	// well-formed but NONEXISTENT id on the same getter — a denied/not-found baseline.
	// The detector uses it deterministically (stage-1 prune) and passes it to the
	// judge (stage 2) to calibrate what "denied/empty" looks like on this server.
	MetadataKeyBOLANegativeControl = "mcptool.bola.negative_control"
	// MetadataKeyBOLANegativeControlError (string) records why the negative-control
	// call failed, when it did. The probe stamps this instead of the denial baseline
	// so a transient failure on the nonexistent-id call is visible (never a silent
	// missing baseline) without failing the whole attempt.
	MetadataKeyBOLANegativeControlError = "mcptool.bola.negative_control_error"
	// MetadataKeyBOLANonexistentID (string) is the well-formed-nonexistent id the
	// probe substituted for the negative control. The detector masks BOTH this id
	// and the target id when comparing the two responses in the stage-1 prune, so a
	// not-found echoing the (different) id still collapses to the same shape. Keeping
	// it in metadata means the detector never re-derives it and stays id-format
	// agnostic.
	MetadataKeyBOLANonexistentID = "mcptool.bola.nonexistent_id"

	// MetadataKeyPathTraversalSignatures holds the []string of well-known file
	// signatures (e.g. "root:x:0:") a mcptool path-traversal probe expects to
	// see in a tool's output if the traversal payload resolved to the target
	// file. Read by the mcptool.PathTraversal detector.
	MetadataKeyPathTraversalSignatures = "mcptool.pathtraversal_signatures"
	// MetadataKeyPathTraversalIsWrite (bool) marks an attempt whose payload
	// targets a canary-write /tmp/proof-<canary> path — evidence of an
	// arbitrary-path WRITE sink rather than an arbitrary-path READ. Read by
	// the detector so a write finding is scored only when accompanied by a
	// tool-side success signal (not a mere echo of the path in an error).
	MetadataKeyPathTraversalIsWrite = "mcptool.pathtraversal_is_write"
	// MetadataKeyPathTraversalToolIsError (bool) is the value of
	// types.ToolResult.IsError from the target's response. When true on a
	// write attempt, the tool refused; the detector suppresses the
	// signature echo in that case (the path we sent appearing in an error
	// message isn't proof of a write).
	MetadataKeyPathTraversalToolIsError = "mcptool.pathtraversal_tool_iserror"

	// MetadataKeyOriginValidationAccepted (bool) records whether the target processed
	// a request that a rebinding-protected MCP server should have refused
	// (external Origin, credentialed CORS reflection, etc). Read by the
	// mcptool.OriginValidation detector.
	MetadataKeyOriginValidationAccepted = "mcptool.originvalidation_accepted"
	// MetadataKeyOriginValidationClass (string) categorises how the attempt bypassed
	// the expected Origin/Host validation. Values are stable strings suitable
	// for grouping in a finding report:
	//
	//	external-origin        server accepted a plausibly-external Origin (root cause)
	//	null-origin            server accepted Origin: null (sandbox iframes, file://)
	//	extension-origin       server accepted a chrome-extension://[uuid] Origin
	//	localhost-lookalike    server accepted an Origin that spoofs "localhost" (weak substring/prefix validator)
	//	case-variant           server accepted a case-shifted variant of the expected host
	//	unexpected-host        server processed a request bearing a non-canonical Host header
	//	cors-reflect-creds     server reflected the attacker Origin AND allow-credentials in an OPTIONS preflight
	//	baseline               spec-compliant baseline (missing Origin) — informational, not a finding
	MetadataKeyOriginValidationClass = "mcptool.originvalidation_class"
	// MetadataKeyOriginValidationOrigin (string) is the Origin header value sent.
	MetadataKeyOriginValidationOrigin = "mcptool.originvalidation_origin"
	// MetadataKeyOriginValidationHost (string) is the Host header value sent.
	MetadataKeyOriginValidationHost = "mcptool.originvalidation_host"
	// MetadataKeyOriginValidationAllowOrigin (string) is the Access-Control-Allow-Origin
	// value the server returned to a preflight request, when present. Recorded
	// even for non-finding attempts because it lets a reviewer confirm a
	// cors-reflect-creds classification.
	MetadataKeyOriginValidationAllowOrigin = "mcptool.originvalidation_allow_origin"
	// MetadataKeyOriginValidationAllowCreds (bool) records whether the response's
	// Access-Control-Allow-Credentials header was true.
	MetadataKeyOriginValidationAllowCreds = "mcptool.originvalidation_allow_credentials" // #nosec G101 -- metadata key name, not a credential
	// MetadataKeyOriginValidationTargetClass (string) categorises the target host
	// so the detector can score findings by exploitability confidence
	// rather than treating every missing-Origin-validation server as an
	// equally-vulnerable DNS-rebinding target. Values:
	//
	//	loopback       127.0.0.0/8, ::1, 0.0.0.0, or literal "localhost".
	//	               Classic DNS-rebinding target — the CVE class.
	//	lan            RFC1918, link-local, or mDNS .local resolving to
	//	               same. Rebinding-exploitable if browsers on same net.
	//	public         Publicly-routable IP or FQDN. DNS rebinding doesn't
	//	               add anything (attacker's page can fetch directly);
	//	               finding is CSRF-class, not rebinding.
	//	unresolvable   DNS lookup failed. Can't classify; treat as
	//	               inconclusive.
	//
	// The detector uses this to emit 1.0 (real rebinding) on
	// loopback/lan and InconclusiveScore (spec violation but
	// exploitability depends on deployment) on public/unresolvable.
	MetadataKeyOriginValidationTargetClass = "mcptool.originvalidation_target_class"

	// MetadataKeySSESessionAccepted (bool) records whether an SSE session-
	// hijack probe attempt succeeded (weakness confirmed). Read by the
	// mcptool.SSESessionHijack detector.
	MetadataKeySSESessionAccepted = "mcptool.sse_session_accepted"
	// MetadataKeySSESessionClass (string) categorises the SSE session
	// weakness the attempt exercised:
	//
	//	session-id-short           IDs shorter than 16 chars (< ~64 bits of state)
	//	session-id-low-entropy     insufficient char-space diversity
	//	session-id-common-prefix   shared prefix across independent sessions
	//	session-id-collision       two independent sessions had the same ID
	//	session-not-tcp-bound      POST accepted from a fresh TCP conn without holding the SSE stream
	//	session-post-close-alive   POST accepted after the SSE stream was closed
	//	baseline                   informational sampling attempt
	MetadataKeySSESessionClass = "mcptool.sse_session_class"
	// MetadataKeySSESessionSample (string) is the session id (or a short
	// preview) the attempt worked with. Recorded for reproducibility; probe
	// output truncates to the first 24 characters.
	MetadataKeySSESessionSample = "mcptool.sse_session_sample"
	// MetadataKeySSESessionEndpoint (string) is the POST endpoint the server
	// advertised for this session (via the `event: endpoint` SSE frame).
	MetadataKeySSESessionEndpoint = "mcptool.sse_session_endpoint"

	// MetadataKeyInconclusive (bool) marks an attempt where the probe was
	// unable to make a confident SAFE/VULN determination — a proxy in path
	// broke a connection-lifetime assumption, a transient network error
	// during sampling, insufficient samples for statistical classification,
	// etc. The corresponding detector emits a non-zero score (see the
	// InconclusiveScore constant in the mcptool detectors) so reports don't
	// hide these under a green SAFE verdict; a reviewer must confirm the
	// finding out-of-band.
	MetadataKeyInconclusive = "mcptool.inconclusive"
	// MetadataKeyInconclusiveReason (string) — human-readable explanation
	// paired with MetadataKeyInconclusive, e.g. "proxy in path: keepalive
	// upstream defeats session-lifetime test" or "<2 SSE samples: cannot
	// assess ID entropy".
	MetadataKeyInconclusiveReason = "mcptool.inconclusive_reason"
)
