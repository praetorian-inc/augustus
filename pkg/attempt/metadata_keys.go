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

	// MetadataKeyInjectionOOBCallback (bool) records whether the mcptool.Injection
	// probe's out-of-band collector received a callback for a shell-command
	// injection payload's canary URL — proof the tool executed an injected OS
	// command that fetched the URL, including the blind case where the tool
	// returns no output. Read by the mcptool.Injection detector.
	MetadataKeyInjectionOOBCallback = "mcptool.injection_oob_callback"
	// MetadataKeyInjectionOOBURL (string) is the canary URL embedded in the
	// command-injection payload for this attempt.
	MetadataKeyInjectionOOBURL = "mcptool.injection_oob_url"

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
	//	origin-validation-sweep  the aggregated Origin/Host bypass finding for the
	//	                         endpoint; carries every crafted value it accepted
	//	                         as evidence (see MetadataKeyOriginValidationVariants)
	//	cors-reflect-creds       server reflected the attacker Origin AND allow-credentials in an OPTIONS preflight
	//	baseline                 spec-compliant baseline (missing Origin) — informational, not a finding
	//
	// The per-variant classes below are NOT attempt classes. They label the
	// individual crafted values inside the aggregated attempt's variant list;
	// a server that validates nothing accepts all of them, so emitting one
	// attempt per variant reported a single flaw as ten findings (LAB-5584):
	//
	//	external-origin        server accepted a plausibly-external Origin (root cause)
	//	null-origin            server accepted Origin: null (sandbox iframes, file://)
	//	extension-origin       server accepted a chrome-extension://[uuid] Origin
	//	localhost-lookalike    server accepted an Origin that spoofs "localhost" (weak substring/prefix validator)
	//	case-variant           server accepted a case-shifted variant of the expected host
	//	unexpected-host        server processed a request bearing a non-canonical Host header
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
	// MetadataKeyOriginValidationVariants ([]map[string]any) carries the
	// per-variant detail of the aggregated Origin/Host sweep — one entry per
	// crafted value the probe sent, each with:
	//
	//	class     the per-variant class (external-origin, null-origin, ...)
	//	origin    the Origin header sent, when the variant set one
	//	host      the Host header sent, when the variant set one
	//	outcome   "accepted" (server served a request it should have refused),
	//	          "refused" (server rejected it), or "not-tested" (the request
	//	          never completed). A tri-state, not a bool: "refused" is
	//	          evidence of validation and "not-tested" is the absence of
	//	          evidence, and conflating them lets an untested variant read
	//	          as a clean result.
	//	result    one-line response summary ("HTTP 200, application/json") or
	//	          the transport error when the request never completed
	//
	// Which variants pass is what tells a remediator whether validation is
	// absent or merely weak — a case-variant-only bypass is a different bug
	// from accepting any origin — so the detail is preserved even though the
	// whole sweep scores as one finding.
	MetadataKeyOriginValidationVariants = "mcptool.originvalidation_variants"
	// MetadataKeyOriginValidationAcceptedClasses ([]string) lists the distinct
	// per-variant classes the endpoint accepted, in sweep order. The fast
	// grouping key for a report that doesn't want to walk the variant list.
	MetadataKeyOriginValidationAcceptedClasses = "mcptool.originvalidation_accepted_classes"
	// MetadataKeyOriginValidationVariantsSent (int) is how many crafted
	// Origin/Host values the sweep sent.
	MetadataKeyOriginValidationVariantsSent = "mcptool.originvalidation_variants_sent"
	// MetadataKeyOriginValidationVariantsAccepted (int) is how many of those
	// the endpoint accepted. Equal to sent means no validation is enforced at
	// all; between 1 and sent means partial validation.
	MetadataKeyOriginValidationVariantsAccepted = "mcptool.originvalidation_variants_accepted"
	// MetadataKeyOriginValidationBaselineAccepted (bool) records whether the
	// endpoint served the plain no-Origin baseline request.
	//
	// This is the fact that makes every other refusal in the sweep
	// interpretable. When it is false the endpoint is refusing the CALLER, not
	// the Origin — an auth gate, an IP allowlist and a dead backend are
	// indistinguishable from Origin enforcement to an outside observer — so
	// refusals of the crafted values are NOT evidence that a validator exists.
	// The detector reads this to score such a sweep inconclusive rather than
	// clean.
	MetadataKeyOriginValidationBaselineAccepted = "mcptool.originvalidation_baseline_accepted"
	// MetadataKeyOriginValidationUntestedClasses ([]string) lists the bypass
	// classes for which NOT ONE variant got a response — checks that never ran,
	// as opposed to a class that was exercised and merely lost a sample.
	MetadataKeyOriginValidationUntestedClasses = "mcptool.originvalidation_untested_classes"
	// MetadataKeyOriginValidationCredentialedRead (bool) records whether the
	// CORS preflight found credentialed reflection of the attacker Origin.
	// Set on the aggregated sweep attempt because it escalates that finding's
	// impact: without it a rebound page drives the tool surface blind; with it
	// the page can also read the responses.
	// Omitted entirely when the preflight did not complete — recording false
	// there would assert an absence the probe never observed.
	MetadataKeyOriginValidationCredentialedRead = "mcptool.originvalidation_credentialed_read" // #nosec G101 -- metadata key name, not a credential

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

	// MetadataKeyPrimitiveCanaries holds the []string of computed-arithmetic
	// canary markers a mcpprimitive probe expects to see in returned content if
	// the server evaluated an injected payload (e.g. a prompt template rendered
	// through an expression engine). The marker never appears in the payload
	// text, so content that merely echoes the injected value cannot match.
	MetadataKeyPrimitiveCanaries = "mcpprimitive.canaries"
	// MetadataKeyPrimitiveSignatures holds the []string of well-known file
	// signatures (e.g. "root:x:0:0:") a mcpprimitive probe expects in returned
	// content if a resource URI resolved to that system file.
	MetadataKeyPrimitiveSignatures = "mcpprimitive.signatures"
	// MetadataKeyPrimitiveOOBCallback (bool) records whether the out-of-band
	// collector received a callback for this attempt's canary URL — proof the
	// server made the request (blind SSRF via resources/read, or blind command
	// execution while rendering a prompt template).
	MetadataKeyPrimitiveOOBCallback = "mcpprimitive.oob_callback"
	// MetadataKeyPrimitiveOOBURL (string) is the canary URL this attempt planted.
	MetadataKeyPrimitiveOOBURL = "mcpprimitive.oob_url"
	// MetadataKeyPrimitiveReflected (bool) records whether the returned content
	// carried the collector's body marker — the non-blind case, where the server
	// fetched the canary URL and handed back its content.
	MetadataKeyPrimitiveReflected = "mcpprimitive.reflected"
	// MetadataKeyPrimitiveClass (string) categorises how the attempt attacked the
	// primitive, for grouping in a finding report. Values are stable strings:
	//
	//	resource-traversal          resource URI escaped its intended scope (arbitrary file read)
	//	resource-template-arg       a resource-template parameter was interpolated into a sink
	//	resource-ssrf               resources/read fetched a caller-supplied URL
	//	resource-content            an advertised resource read as-is (no payload), so
	//	                            its served body can be scored for smuggled instructions
	//	prompt-content              an argument-less prompt template rendered as-is, same purpose
	//	prompt-template-injection   prompts/get evaluated an argument (SSTI/eval)
	//	prompt-command-injection    prompts/get executed an OS command while rendering
	MetadataKeyPrimitiveClass = "mcpprimitive.class"
	// MetadataKeyPrimitiveTarget (string) is the primitive attacked — the resource
	// URI requested, or the prompt-template name rendered.
	MetadataKeyPrimitiveTarget = "mcpprimitive.target"
	// MetadataKeyPrimitiveArg (string) is the prompt-template argument the payload
	// was injected into. Absent for resource attempts, which carry no arguments.
	MetadataKeyPrimitiveArg = "mcpprimitive.arg"
	// MetadataKeyPrimitiveCallError (string) records the server's refusal for a
	// call that returned a JSON-RPC error. resources/read and prompts/get have no
	// application-level error flag (unlike tools/call), so a denial arrives as an
	// error — preserving it keeps a refusal visible to a reviewer instead of
	// collapsing it into a silent non-finding.
	MetadataKeyPrimitiveCallError = "mcpprimitive.call_error"
	// MetadataKeyPrimitiveMIMEType (string) is the MIME type the server declared for
	// the first returned content block.
	MetadataKeyPrimitiveMIMEType = "mcpprimitive.mime_type"
)
