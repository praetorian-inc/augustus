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
	// toolsec injection probe expects to see in a tool's output if the tool
	// evaluated the injected payload. Read by the toolsec.Injection detector.
	MetadataKeyInjectionCanaries = "toolsec.injection_canaries"

	// MetadataKeySSRFCallback (bool) records whether the toolsec.SSRF probe's
	// out-of-band collector received a callback for this attempt's canary URL —
	// proof of server-side request forgery, including the blind case.
	MetadataKeySSRFCallback = "toolsec.ssrf_callback"
	// MetadataKeySSRFReflected (bool) records whether the tool's response
	// contained the collector's body marker (non-blind SSRF: the tool fetched
	// the URL and returned its content).
	MetadataKeySSRFReflected = "toolsec.ssrf_reflected"
	// MetadataKeySSRFOOBURL (string) is the canary URL injected for this attempt.
	MetadataKeySSRFOOBURL = "toolsec.ssrf_oob_url"

	// MetadataKeyBOLAID (string) is the victim object identifier the toolsec.BOLA
	// probe called a getter with under the attacker's identity.
	MetadataKeyBOLAID = "toolsec.bola.id"
	// MetadataKeyBOLAVictimIdentity (string) labels the identity that owns the
	// object the attacker attempted to read.
	MetadataKeyBOLAVictimIdentity = "toolsec.bola.victim_identity"
	// MetadataKeyBOLAPositiveControl (string) is the attacker's OWN-object response
	// for the same getter — a served baseline the toolsec.BOLA detector's judge uses
	// to calibrate what "served" looks like on this server. Absent when the attacker
	// owns no object for that getter.
	MetadataKeyBOLAPositiveControl = "toolsec.bola.positive_control"
	// MetadataKeyBOLANegativeControl (string) is the attacker's response for a
	// well-formed but NONEXISTENT id on the same getter — a denied/not-found baseline.
	// The detector uses it deterministically (stage-1 prune) and passes it to the
	// judge (stage 2) to calibrate what "denied/empty" looks like on this server.
	MetadataKeyBOLANegativeControl = "toolsec.bola.negative_control"
	// MetadataKeyBOLANegativeControlError (string) records why the negative-control
	// call failed, when it did. The probe stamps this instead of the denial baseline
	// so a transient failure on the nonexistent-id call is visible (never a silent
	// missing baseline) without failing the whole attempt.
	MetadataKeyBOLANegativeControlError = "toolsec.bola.negative_control_error"
	// MetadataKeyBOLANonexistentID (string) is the well-formed-nonexistent id the
	// probe substituted for the negative control. The detector masks BOTH this id
	// and the target id when comparing the two responses in the stage-1 prune, so a
	// not-found echoing the (different) id still collapses to the same shape. Keeping
	// it in metadata means the detector never re-derives it and stays id-format
	// agnostic.
	MetadataKeyBOLANonexistentID = "toolsec.bola.nonexistent_id"

	// MetadataKeyPathTraversalSignatures holds the []string of well-known file
	// signatures (e.g. "root:x:0:") a toolsec path-traversal probe expects to
	// see in a tool's output if the traversal payload resolved to the target
	// file. Read by the toolsec.PathTraversal detector.
	MetadataKeyPathTraversalSignatures = "toolsec.pathtraversal_signatures"

	// MetadataKeyDNSRebindAccepted (bool) records whether the target processed
	// a request that a rebinding-protected MCP server should have refused
	// (external Origin, credentialed CORS reflection, etc). Read by the
	// toolsec.DNSRebinding detector.
	MetadataKeyDNSRebindAccepted = "toolsec.dnsrebind_accepted"
	// MetadataKeyDNSRebindClass (string) categorises how the attempt bypassed
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
	MetadataKeyDNSRebindClass = "toolsec.dnsrebind_class"
	// MetadataKeyDNSRebindOrigin (string) is the Origin header value sent.
	MetadataKeyDNSRebindOrigin = "toolsec.dnsrebind_origin"
	// MetadataKeyDNSRebindHost (string) is the Host header value sent.
	MetadataKeyDNSRebindHost = "toolsec.dnsrebind_host"
	// MetadataKeyDNSRebindAllowOrigin (string) is the Access-Control-Allow-Origin
	// value the server returned to a preflight request, when present. Recorded
	// even for non-finding attempts because it lets a reviewer confirm a
	// cors-reflect-creds classification.
	MetadataKeyDNSRebindAllowOrigin = "toolsec.dnsrebind_allow_origin"
	// MetadataKeyDNSRebindAllowCreds (bool) records whether the response's
	// Access-Control-Allow-Credentials header was true.
	MetadataKeyDNSRebindAllowCreds = "toolsec.dnsrebind_allow_credentials"

	// MetadataKeySSESessionAccepted (bool) records whether an SSE session-
	// hijack probe attempt succeeded (weakness confirmed). Read by the
	// toolsec.SSESessionHijack detector.
	MetadataKeySSESessionAccepted = "toolsec.sse_session_accepted"
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
	MetadataKeySSESessionClass = "toolsec.sse_session_class"
	// MetadataKeySSESessionSample (string) is the session id (or a short
	// preview) the attempt worked with. Recorded for reproducibility; probe
	// output truncates to the first 24 characters.
	MetadataKeySSESessionSample = "toolsec.sse_session_sample"
	// MetadataKeySSESessionEndpoint (string) is the POST endpoint the server
	// advertised for this session (via the `event: endpoint` SSE frame).
	MetadataKeySSESessionEndpoint = "toolsec.sse_session_endpoint"

	// MetadataKeyInconclusive (bool) marks an attempt where the probe was
	// unable to make a confident SAFE/VULN determination — a proxy in path
	// broke a connection-lifetime assumption, a transient network error
	// during sampling, insufficient samples for statistical classification,
	// etc. The corresponding detector emits a non-zero score (see the
	// InconclusiveScore constant in the toolsec detectors) so reports don't
	// hide these under a green SAFE verdict; a reviewer must confirm the
	// finding out-of-band.
	MetadataKeyInconclusive = "toolsec.inconclusive"
	// MetadataKeyInconclusiveReason (string) — human-readable explanation
	// paired with MetadataKeyInconclusive, e.g. "proxy in path: keepalive
	// upstream defeats session-lifetime test" or "<2 SSE samples: cannot
	// assess ID entropy".
	MetadataKeyInconclusiveReason = "toolsec.inconclusive_reason"
)
