package mcpprobe

// Attempt-metadata keys for the MCP authentication / authorization probe family
// (LAB-5569). They live here, rather than being duplicated per package, because
// each key is written by a probe in internal/probes/... and read by its detector
// in internal/detectors/..., so a single definition is what keeps the two halves
// from silently drifting apart on a typo.
const (
	// MetaAuthClass (string) categorises what an attempt tested, so a report can
	// group by concrete weakness and score by severity tier rather than lumping
	// every result into one verdict. See the AuthClass* values.
	MetaAuthClass = "mcpauthz.class"

	// MetaAuthCredentialsConfigured (bool) records whether the operator
	// configured any credentials for this target.
	//
	// This is the precondition for the whole family. Anonymous success against a
	// target nobody gave credentials for is trivially true and worthless; the
	// finding is that a configured boundary was bypassed. A detector must never
	// score a differential as VULN when this is false.
	MetaAuthCredentialsConfigured = "mcpauthz.credentials_configured"

	// MetaAuthCredentialHeaders (string) names the credential-bearing headers the
	// operator configured, comma-separated. Names only — never values — so the
	// evidence explains WHICH boundary was bypassed without storing a secret.
	MetaAuthCredentialHeaders = "mcpauthz.credential_headers"

	// MetaAuthAnonymousSucceeded (bool) records whether the equivalent request
	// succeeded over a session carrying no credentials.
	MetaAuthAnonymousSucceeded = "mcpauthz.anonymous_succeeded"

	// MetaAuthAuthenticatedSucceeded (bool) records whether the same operation
	// succeeded over the operator's authenticated session — the control that
	// proves the probe was able to exercise the target at all. Anonymous success
	// while this is false is suspect (the endpoint may be answering everything
	// with an error) and is scored inconclusive, not vulnerable.
	MetaAuthAuthenticatedSucceeded = "mcpauthz.authenticated_succeeded"

	// MetaAuthTargetClass (string) buckets the endpoint host by reachability:
	// "loopback", "lan", "public", "unresolvable". A publicly reachable server
	// with a decorative auth boundary is critical; a loopback development server
	// behaving identically is expected and scored inconclusive.
	MetaAuthTargetClass = "mcpauthz.target_class"

	// MetaAuthTool (string) is the tool an attempt invoked, when any.
	MetaAuthTool = "mcpauthz.tool"

	// MetaAuthParam (string) is the tool parameter an attempt targeted, when any.
	MetaAuthParam = "mcpauthz.param"

	// MetaAuthControl (string) is the response the CONTROL call returned — the
	// baseline an attempt's own output is compared against. Adjudication is a
	// comparison between the two recorded responses, never a search for a
	// success or denial string, so it carries no server-specific assumptions.
	MetaAuthControl = "mcpauthz.control_response"

	// MetaAuthControlLabel (string) describes, in plain words, what the control
	// call was, so a reviewer can read the evidence without the probe source.
	MetaAuthControlLabel = "mcpauthz.control_label"

	// MetaAuthProbeValue (string) is the value the attempt sent in the targeted
	// parameter. Recorded so the detector can mask it out of both responses
	// before comparing them: servers routinely echo the submitted value, which
	// would otherwise make every response differ and defeat the comparison.
	MetaAuthProbeValue = "mcpauthz.probe_value"

	// MetaAuthControlValue (string) is the value the control call sent in the
	// same parameter, masked for the same reason.
	MetaAuthControlValue = "mcpauthz.control_value"

	// MetaAuthReplicaMatched (bool) records whether a SECOND, independently
	// generated value of the same shape produced the same response as the first.
	//
	// It is what separates "the target's answer depends on the value's SHAPE"
	// from an unstable or randomly varying endpoint. Two independent random
	// values were both certainly never issued, so a target performing a real
	// issuance lookup must answer them the same way it answers any other
	// unissued value.
	MetaAuthReplicaMatched = "mcpauthz.replica_matched"

	// MetaAuthDeclaredValues (string) lists the values the target itself declared
	// for the parameter (JSON-schema enum, or values documented in its
	// description), comma-separated. Recorded so a reviewer can confirm the probe
	// tried what the target advertised rather than a guessed vocabulary.
	MetaAuthDeclaredValues = "mcpauthz.declared_values"
)

// Attempt classes. Each names a distinct weakness so findings group by cause and
// score by severity, rather than collapsing into a single verdict.
const (
	// AuthClassAuthBaseline is the authenticated control. Informational only: it
	// establishes that the target is reachable and answers the operator, and is
	// never itself a finding.
	AuthClassAuthBaseline = "auth-baseline"

	// AuthClassAnonEnumeration is catalog enumeration over a credential-free
	// session. Serious: it discloses the target's whole attack surface to an
	// unauthenticated caller and needs no state change to prove, which is why it
	// carries the headline finding.
	AuthClassAnonEnumeration = "anon-enumeration"

	// AuthClassAnonInvocation is a read-only tool invocation over a
	// credential-free session. Critical: it proves the unauthenticated caller can
	// make the server ACT, not merely describe itself.
	AuthClassAnonInvocation = "anon-invocation"

	// AuthClassTokenFormatOnly is a verification surface that accepts a
	// well-formed but never-issued value — validating a value's shape instead of
	// whether it was ever issued.
	AuthClassTokenFormatOnly = "token-format-only"

	// AuthClassTokenPredictable is an issuing surface whose tokens are related
	// across two closely-spaced requests, so one holder can derive another's.
	AuthClassTokenPredictable = "token-predictable"

	// AuthClassCredentialPresence is a privileged operation where the mere
	// PRESENCE of a credential parameter changes the outcome, regardless of the
	// value — the parameter is checked for existence, not validity.
	AuthClassCredentialPresence = "credential-presence"

	// AuthClassPrivilegeDiscriminator is a parameter that selects an authority
	// level, where some value reaches behaviour the target's own declared values
	// do not. The finding is the differential in authorization behaviour, never
	// the presence of any particular string.
	AuthClassPrivilegeDiscriminator = "privilege-discriminator"
)
