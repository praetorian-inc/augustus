package mcptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// originValidationTargetClass tags an endpoint host by DNS-rebinding relevance.
// See MetadataKeyOriginValidationTargetClass for what each value means.
type originValidationTargetClass string

const (
	targetLoopback     originValidationTargetClass = "loopback"
	targetLAN          originValidationTargetClass = "lan"
	targetPublic       originValidationTargetClass = "public"
	targetUnresolvable originValidationTargetClass = "unresolvable"
)

// classifyTargetHost inspects the endpoint host and buckets it by DNS-
// rebinding relevance. Order of decision:
//
//  1. Literal "localhost" or "0.0.0.0" → loopback (even before resolution).
//  2. Parse as IP. If success, classify by IP class (loopback / RFC1918 /
//     link-local / else public).
//  3. Otherwise DNS-resolve. If ANY resolved IP is loopback, treat as
//     loopback (worst case wins for exploitability). Else if any is LAN,
//     LAN. Else public.
//  4. Resolution failure → unresolvable.
//
// This is the single-shot exploitability heuristic; the detector uses
// the returned class to decide whether a missing-Origin finding scores
// as full VULN (loopback/lan, real DNS rebinding) or inconclusive
// (public/unresolvable, CSRF-class or unknown deployment context).
func classifyTargetHost(ctx context.Context, host string) originValidationTargetClass {
	if host == "" {
		return targetUnresolvable
	}
	// Strip port if present.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// Strip brackets from IPv6 literals.
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "0.0.0.0" || strings.HasSuffix(lower, ".localhost") {
		return targetLoopback
	}
	// mDNS .local — assume LAN (usually rebindable when browsers share the
	// same LAN).
	if strings.HasSuffix(lower, ".local") {
		return targetLAN
	}
	// If host parses as an IP directly, classify from it.
	if ip := net.ParseIP(host); ip != nil {
		return classifyIP(ip)
	}
	// Hostname → context-aware DNS lookup so a slow resolver can't outlive
	// the probe context (fixes CodeRabbit #7). Worst class wins.
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return targetUnresolvable
	}
	worst := targetPublic
	for _, a := range addrs {
		c := classifyIP(a.IP)
		if rank(c) < rank(worst) {
			worst = c
		}
	}
	return worst
}

// classifyIP buckets a single IP.
func classifyIP(ip net.IP) originValidationTargetClass {
	if ip.IsLoopback() || ip.Equal(net.IPv4zero) || ip.Equal(net.IPv6unspecified) {
		return targetLoopback
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return targetLAN
	}
	if ip.IsPrivate() {
		return targetLAN
	}
	return targetPublic
}

// rank orders classes worst-first for the "worst-of-many" resolution rule.
// Lower rank = higher exploitability concern.
func rank(c originValidationTargetClass) int {
	switch c {
	case targetLoopback:
		return 0
	case targetLAN:
		return 1
	case targetPublic:
		return 2
	default:
		return 3
	}
}

func init() {
	probes.Register("mcptransport.OriginValidation", NewOriginValidation)
}

var _ types.ProbeMetadata = (*OriginValidation)(nil)

// OriginValidation probes an MCP HTTP endpoint for the server-side precondition of
// browser DNS-rebinding attacks: a target that accepts a request bearing an
// Origin (or Host) that a spec-compliant, allowlist-based validator would
// refuse.
//
// The probe is designed against how those validators are actually written:
//
//   - a strict-string allowlist (the shape shipped in patched MCP TypeScript
//     SDK 1.24 and the Java SDK 1.0 defence-in-depth PRs)
//   - a "$2 WAF" that substring-matches known-bad tokens like "attacker" or
//     "evil" (trivially bypassed and effectively no protection)
//   - a naive validator that uses contains/startsWith/case-insensitive match
//     over "localhost" or the expected hostname
//   - a CORS layer that reflects the request Origin plus credentials — the
//     mechanism that lets a browser attacker read the response, not just send
//     the request
//
// Payloads are randomised per run using RFC 2606-reserved test domains, so no
// value the probe sends is a static regex match for a signature-based WAF —
// yet every value is a domain a real attacker could plausibly control.
type OriginValidation struct {
	endpointOverride string
	timeout          time.Duration
	// nonce is used to build randomised Origin/Host values so the probe never
	// sends the same wire-string twice across runs, defeating cheap blocklist
	// WAFs and letting re-scans confirm intermittent behaviour.
	nonce string
}

// NewOriginValidation constructs the probe. The endpoint is resolved from the
// target generator when it implements types.MCPEndpoint; the "endpoint" config
// key overrides that when set. Proxy, TLS, and per-request headers are
// inherited from the target generator's HTTPClient — configure them there,
// not on this probe.
func NewOriginValidation(cfg registry.Config) (probes.Prober, error) {
	return &OriginValidation{
		endpointOverride: registry.GetString(cfg, "endpoint", ""),
		timeout:          time.Duration(registry.GetInt(cfg, "request_timeout", 10)) * time.Second,
		nonce:            randToken(),
	}, nil
}

func (p *OriginValidation) Name() string { return "mcptransport.OriginValidation" }

var _ types.RiskDescriber = (*OriginValidation)(nil)

// RiskInfo is the curated security write-up for this probe's finding.
func (p *OriginValidation) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description:    "An MCP HTTP/SSE endpoint does not validate the Origin (and Host) header the MCP specification requires it to enforce, accepting requests with foreign Origin/Host values a compliant server would reject. Because the endpoint binds to a loopback or private-network address, this is a precondition for DNS rebinding.",
		Impact:         "A web page the victim visits can reach the local MCP endpoint from the victim's browser and drive its tool surface from outside the assumed local-only boundary. Where credentialed CORS reflection is present, the responses are also exposed to the attacker's origin.",
		Recommendation: "Allowlist permitted Origin and Host values on every MCP HTTP/SSE request and reject anything else. Don't reflect an arbitrary origin into Access-Control-Allow-Origin, and never pair a reflected origin with Access-Control-Allow-Credentials. Require a per-session token a cross-origin page can't obtain.",
		References:     "https://cwe.mitre.org/data/definitions/346.html\nhttps://cwe.mitre.org/data/definitions/350.html\nhttps://cwe.mitre.org/data/definitions/942.html\nhttps://nvd.nist.gov/vuln/detail/CVE-2025-49596",
		Taxonomies:     "- cwe: 346\n- cwe: 350\n- cwe: 942",
		CVSSVector:     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
		Verification: "## How this is confirmed\n\n" +
			"Augustus sends a sweep of requests carrying foreign `Origin` (and `Host`) header values that a specification-compliant MCP server must reject, and observes the endpoint accept them. The whole sweep is reported as a single finding for the endpoint — every crafted value it accepted is listed in the evidence, since which ones get through is what distinguishes an endpoint with no validation from one whose allowlist is merely weak. Because the endpoint binds a loopback or private-network address, this is the precondition for a browser DNS-rebinding attack (CVE-2025-49596 class). On a loopback / RFC1918 target the finding is scored full; on a public endpoint the same wire result is CSRF-class and scored inconclusive, since exploitability depends on cookie/auth context the probe cannot inspect.\n\n" +
			"## Reproduce\n\n" +
			"Re-run the `mcptransport.OriginValidation` probe against the affected endpoint via the `mcp.MCP` generator. The endpoint returns a success response to a request bearing a foreign Origin/Host it should have rejected.",
	}
}

func (p *OriginValidation) Description() string {
	return "Tests MCP HTTP endpoints for missing Origin/Host validation — the mitigation MCP servers must implement to block browser DNS-rebinding attacks (CVE-2025-49596 class). Classifies the target host at probe time: loopback / RFC1918-LAN targets get full-VULN scoring because they are the browser-driven-rebinding attack path; public endpoints get inconclusive scoring because the same wire finding is CSRF-class rather than rebinding-class there, and exploitability depends on cookie/auth deployment context the probe cannot inspect."
}

func (p *OriginValidation) Goal() string {
	return "Determine whether the MCP HTTP endpoint enforces the Origin/Host validation the MCP spec requires. Score = 1.0 on loopback/LAN targets (real DNS-rebinding precondition), InconclusiveScore on public/unresolvable targets (spec violation with different attack-class implications)."
}

func (p *OriginValidation) GetPrimaryDetector() string { return "mcptransport.OriginValidation" }

func (p *OriginValidation) GetPrompts() []string {
	return []string{"Randomised MCP initialize + CORS preflight bearing Origin/Host values a rebinding-protected server should refuse"}
}

// originValidationClass is a stable classifier for a bypass. classBaseline,
// classSweep and classCORSReflectCreds label whole attempts; the rest label
// individual crafted values *inside* the sweep attempt's variant list.
//
// The per-variant classes were once attempt classes too, one attempt each.
// That reported a single flaw as ten findings: a server that validates
// nothing accepts every variant, so ten identical 1.0 rows drowned every
// other result in an MCP scan (LAB-5584). They are ten proofs of one
// property, and they now travel as evidence on one finding.
type originValidationClass string

const (
	classBaseline           originValidationClass = "baseline"
	classSweep              originValidationClass = "origin-validation-sweep"
	classExternalOrigin     originValidationClass = "external-origin"
	classNullOrigin         originValidationClass = "null-origin"
	classExtensionOrigin    originValidationClass = "extension-origin"
	classLocalhostLookalike originValidationClass = "localhost-lookalike"
	classCaseVariant        originValidationClass = "case-variant"
	classUnexpectedHost     originValidationClass = "unexpected-host"
	classCORSReflectCreds   originValidationClass = "cors-reflect-creds" // #nosec G101 -- classification tag, not a credential
)

// mcpInitializePayload is the smallest MCP initialize the server must be
// willing to answer to demonstrate that it accepted our request. The exact
// protocol version matters less than whether the server processes the
// JSON-RPC at all; a server that would refuse this on Origin grounds returns
// 403 or a CORS-style rejection, not a well-formed initialize result.
const mcpInitializePayload = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"augustus-scan","version":"1.0"}}}`

// buildOriginPayloads renders every Origin bypass class as a concrete header
// value against a fresh per-run nonce. RFC 2606 reserved test domains
// (example.com/.net/.org) ensure the values are non-routable *and* look like
// benign analytics / CDN traffic to any string-blocklist WAF.
func (p *OriginValidation) buildOriginPayloads() []originPayload {
	tag := p.nonce[:8]
	return []originPayload{
		// External origin — the primary finding. A random subdomain of an
		// RFC 2606 domain so no static blocklist ("evil", "attacker", ...)
		// hits, yet every request is unambiguously cross-origin.
		{class: classExternalOrigin, value: "https://" + tag + ".example.com"},
		{class: classExternalOrigin, value: "https://cdn-" + tag + ".example.net"},
		// null: what browsers send from sandbox iframes and file:// contexts.
		// Some naive validators explicitly allow "null" for tests and never
		// remove it; a rebinding-capable page can force this via iframe.
		{class: classNullOrigin, value: "null"},
		// Extension origin — a real malicious-extension shape. Attackers who
		// ship a rogue extension get to pick the Origin, and it looks like
		// this. UUID-shaped to blend with legitimate extension traffic.
		{class: classExtensionOrigin, value: "chrome-extension://" + extensionID(tag)},
		{class: classExtensionOrigin, value: "moz-extension://" + extensionUUID(tag)},
		// Localhost-lookalike — catches validators that use
		// contains("localhost") / startsWith("localhost") / suffix match.
		// A real attacker can register any of these because they are only
		// meaningful *relative* to the string check.
		{class: classLocalhostLookalike, value: "http://localhost." + tag + ".example.com"},
		{class: classLocalhostLookalike, value: "http://127.0.0.1." + tag + ".example.net"},
	}
}

// buildHostPayloads renders unexpected Host header values. These test whether
// the server enforces a Host allowlist independent of Origin (some SDKs do
// both, some only one). Values are RFC 2606-reserved and randomised.
func (p *OriginValidation) buildHostPayloads() []hostPayload {
	tag := p.nonce[:8]
	return []hostPayload{
		{class: classUnexpectedHost, value: tag + ".example.com"},
		// Sub-127.0.0.1 label — same trick as localhost-lookalike but at the
		// Host layer.
		{class: classUnexpectedHost, value: "127.0.0.1." + tag + ".example.net"},
	}
}

type originPayload struct {
	class originValidationClass
	value string
}

type hostPayload struct {
	class originValidationClass
	value string
}

// extensionID returns a Chrome-extension-id-shaped string (32 lowercase
// letters). The exact byte pattern doesn't matter to the target; the shape
// does, so a shape-matching validator ("looks like an extension id → allow")
// exposes itself.
func extensionID(seed string) string {
	// Guard against an empty seed — i%len(seed) would panic with a slice
	// index out of range. In practice the caller (Probe) always passes a
	// 16-hex-char randToken() output, but defensive belt for direct-test
	// paths and future callers.
	if seed == "" {
		seed = "0123456789abcdef"
	}
	// Deterministic-per-seed but uses the seed's bytes to fill 32 letters.
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		c := seed[i%len(seed)]
		if c >= '0' && c <= '9' {
			c = 'a' + (c - '0')
		}
		if c < 'a' || c > 'p' {
			c = 'a' + (c % 16)
		}
		out[i] = c
	}
	return string(out)
}

// extensionUUID renders the seed as an 8-4-4-4-12 UUID-shaped hex string.
func extensionUUID(seed string) string {
	// Pad or truncate seed to 32 hex-shaped chars, then insert dashes.
	src := (seed + "0123456789abcdef0123456789abcdef")[:32]
	return src[:8] + "-" + src[8:12] + "-" + src[12:16] + "-" + src[16:20] + "-" + src[20:32]
}

// Probe resolves the endpoint and runs the full sweep. Returns no attempts (no
// error) for non-HTTP transports or absent endpoints.
func (p *OriginValidation) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	endpoint := p.resolveEndpoint(gen)
	if endpoint == "" {
		return nil, nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("mcptransport.OriginValidation: parse endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		slog.Warn("mcptransport.OriginValidation: skipping non-HTTP transport", "endpoint", endpoint)
		return nil, nil
	}
	// Pick the request shape from the transport. The security question is the
	// same for both — does the server serve this request when the Origin is
	// attacker-controlled? — but the HTTP fingerprint differs:
	//
	//   streamable HTTP  POST endpoint  with JSON-RPC initialize; acceptance
	//                    is a JSON-RPC (or SSE) 200 response.
	//   legacy SSE       GET /sse; acceptance is 200 with a text/event-stream
	//                    response (the server started serving the stream
	//                    before we could get a session).
	//
	// A browser DNS-rebinding attacker gets exactly one HTTP round trip after
	// the rebind; whether they use GET /sse or POST /message doesn't matter
	// to the Origin check that runs BEFORE either handler.
	transport := "http"
	if mcpEnd, ok := gen.(types.MCPEndpoint); ok && mcpEnd.Transport() == "sse" {
		transport = "sse"
	}

	// Classify the target's host BEFORE sending anything. The class flows
	// into every attempt's metadata; the detector uses it to distinguish
	// real DNS-rebinding preconditions (loopback/LAN) from spec-violation-
	// only findings on public endpoints (CSRF-class, not rebinding, needs
	// deployment context to assess).
	targetClass := classifyTargetHost(ctx, u.Host)
	slog.Info("mcptransport.OriginValidation: target host classified",
		"host", u.Host, "class", string(targetClass))

	client, err := p.borrowHTTPClient(gen)
	if err != nil {
		return nil, err
	}
	var attempts []*attempt.Attempt

	// Helper: every attempt inherits the target class so the detector can
	// score by exploitability.
	stampClass := func(a *attempt.Attempt) *attempt.Attempt {
		a.Metadata[attempt.MetadataKeyOriginValidationTargetClass] = string(targetClass)
		return a
	}

	// 1. Baseline: no Origin. Spec-compliant servers pass this; if it fails,
	// we can't distinguish "server rejected our headers" from "server can't
	// accept us at all," so the whole sweep is inconclusive. We record the
	// attempt either way.
	base := stampClass(p.attemptFromVariant(p.sendVariant(ctx, client, endpoint, transport, "", "", classBaseline)))
	attempts = append(attempts, base)
	if !metaBool(base, attempt.MetadataKeyOriginValidationAccepted) {
		slog.Info("mcptransport.OriginValidation: baseline (no Origin) not accepted; downstream bypass results may be inconclusive", "endpoint", endpoint, "transport", transport)
	}

	// 2-4. The bypass sweep. Every variant below asks the SAME question — does
	// this endpoint enforce the Origin/Host allowlist the spec requires — so
	// the results are collected here and folded into a single finding after
	// the preflight, rather than emitted one attempt per variant (LAB-5584).
	var variants []variantResult

	// 2. Origin bypass sweep.
	for _, o := range p.buildOriginPayloads() {
		variants = append(variants, p.sendVariant(ctx, client, endpoint, transport, o.value, "", o.class))
	}

	// 3. Case-variant of the expected host — tests case-sensitive vs
	// insensitive matching against whatever hostname the server considers
	// canonical. Case-shifted request Origin matches the target's host with
	// scheme forced to http.
	//
	// Skip when the host is all-numeric (e.g. "127.0.0.1:9003") — swapCase
	// is a no-op there, so we'd send the server's OWN canonical Origin and
	// a correctly-hardened allowlist server would accept it, giving a false
	// positive on the case-variant class.
	if u.Host != "" {
		caseHost := swapCase(u.Host)
		if caseHost != u.Host {
			variants = append(variants, p.sendVariant(ctx, client, endpoint, transport, "http://"+caseHost, "", classCaseVariant))
		}
	}

	// 4. Host header sweep.
	for _, h := range p.buildHostPayloads() {
		variants = append(variants, p.sendVariant(ctx, client, endpoint, transport, "", h.value, h.class))
	}

	// 5. CORS preflight — OPTIONS with an external Origin, inspect
	// Access-Control-Allow-Origin echo + Allow-Credentials. A server that
	// reflects the attacker Origin with credentials is exploitable regardless
	// of whether the POST body succeeds, because a browser DNS-rebinding
	// attacker can read the response. Sent before the sweep is aggregated so
	// its outcome can escalate the aggregated finding's stated impact.
	preflight := stampClass(p.probePreflight(ctx, client, endpoint, "https://"+p.nonce[:8]+".example.org", u.Host))

	// 6. One finding for the endpoint, carrying every variant as evidence.
	if agg := p.aggregateSweep(endpoint, transport, variants, corsResultFrom(preflight)); agg != nil {
		attempts = append(attempts, stampClass(agg))
	}
	attempts = append(attempts, preflight)

	return attempts, nil
}

// variantResult is the outcome of one crafted Origin/Host value. The sweep
// collects these rather than emitting an attempt each, because ten variants
// are ten proofs of one property and a server that validates nothing answers
// all ten identically — see the originValidationClass doc comment.
type variantResult struct {
	class    originValidationClass
	origin   string
	host     string
	accepted bool
	// transcript is the full request/response record, including the response
	// body (streamable-HTTP only). Carried on the baseline attempt as its
	// output, and on the aggregate for one representative accepted variant.
	transcript string
	// result is the one-line response summary shown in the aggregated
	// evidence table, or the transport error when the request never landed.
	result string
	err    error
}

// Variant outcomes carried in the aggregated finding's evidence. "accepted"
// and "refused" are both observations the probe made; "not-tested" is the
// absence of one. They must stay distinct for the same reason corsReflection
// is a tri-state rather than a bool: a consumer reading accepted==false could
// not tell "the server refused this value" from "we never found out", and the
// second is not evidence of validation.
const (
	variantAccepted  = "accepted"
	variantRefused   = "refused"
	variantNotTested = "not-tested"
)

// outcome collapses the variant to the tri-state recorded in the evidence.
func (v variantResult) outcome() string {
	switch {
	case v.err != nil:
		return variantNotTested
	case v.accepted:
		return variantAccepted
	default:
		return variantRefused
	}
}

// corsReflection is the tri-state outcome of the credentialed-CORS preflight.
// "Not tested" must stay distinct from "absent": a preflight that never
// completed tells us nothing about the endpoint, and reporting that as an
// absence understates the aggregated finding's impact.
type corsReflection int

const (
	corsNotTested corsReflection = iota
	corsAbsent
	corsPresent
)

// corsResultFrom derives the tri-state from the preflight attempt. An errored
// preflight is "not tested", NOT "no reflection".
func corsResultFrom(preflight *attempt.Attempt) corsReflection {
	if preflight == nil || preflight.Status == attempt.StatusError {
		return corsNotTested
	}
	if metaBool(preflight, attempt.MetadataKeyOriginValidationAccepted) {
		return corsPresent
	}
	return corsAbsent
}

// aggregateSweep folds the whole bypass sweep into the single scored attempt
// for this endpoint. Returns nil when the sweep sent nothing (no variants
// were applicable), so callers don't emit an empty finding.
//
// The attempt scores through the ordinary detector path: class is not
// "baseline", and the accepted flag is true when ANY variant was accepted.
// The target-class severity tiering is untouched — the caller stamps it on
// this attempt exactly as it does on every other.
func (p *OriginValidation) aggregateSweep(endpoint, transport string, variants []variantResult, cors corsReflection) *attempt.Attempt {
	if len(variants) == 0 {
		return nil
	}

	var (
		accepted []variantResult
		rejected []variantResult
		errored  []variantResult
		// Empty, not nil: a server that refuses everything accepts no class,
		// and that is the COMMON case on a healthy target. A nil slice
		// marshals to JSON null, so a consumer iterating accepted_classes
		// would blow up on exactly the endpoints that are fine.
		acceptedClass  = make([]string, 0, len(variants))
		seenClass      = map[originValidationClass]bool{}
		variantDetails = make([]map[string]any, 0, len(variants))
	)
	for _, v := range variants {
		detail := map[string]any{
			"class":   string(v.class),
			"outcome": v.outcome(),
			"result":  v.result,
		}
		if v.origin != "" {
			detail["origin"] = v.origin
		}
		if v.host != "" {
			detail["host"] = v.host
		}
		variantDetails = append(variantDetails, detail)

		switch v.outcome() {
		case variantNotTested:
			errored = append(errored, v)
		case variantAccepted:
			accepted = append(accepted, v)
			if !seenClass[v.class] {
				seenClass[v.class] = true
				acceptedClass = append(acceptedClass, string(v.class))
			}
		default:
			rejected = append(rejected, v)
		}
	}

	a := attempt.New(describeSweep(len(accepted), len(variants)))
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeyOriginValidationClass] = string(classSweep)
	a.Metadata[attempt.MetadataKeyOriginValidationVariants] = variantDetails
	a.Metadata[attempt.MetadataKeyOriginValidationAcceptedClasses] = acceptedClass
	a.Metadata[attempt.MetadataKeyOriginValidationVariantsSent] = len(variants)
	a.Metadata[attempt.MetadataKeyOriginValidationVariantsAccepted] = len(accepted)
	// Only claim a credentialed-read verdict when the preflight actually ran.
	// Recording false for an untested preflight would assert an absence we
	// never observed.
	if cors != corsNotTested {
		a.Metadata[attempt.MetadataKeyOriginValidationCredentialedRead] = cors == corsPresent
	}
	untested := untestedClasses(variants)
	a.AddOutput(renderSweepEvidence(endpoint, transport, accepted, rejected, errored, cors, untested))

	// Every variant failed at the transport — the endpoint was never actually
	// tested. Reporting that as SAFE would hide a broken scan behind a green
	// row, so it surfaces as an errored attempt with no accept/reject verdict.
	if len(errored) == len(variants) {
		a.SetError(fmt.Errorf("all %d Origin/Host variants failed in transit; first error: %w", len(variants), errored[0].err))
		return a
	}

	a.Complete()
	a.Metadata[attempt.MetadataKeyOriginValidationAccepted] = len(accepted) > 0

	// A whole bypass class went untested — every variant of it died in
	// transit — and nothing else was accepted. That is a check this sweep
	// never ran, not merely a lost sample, so "the endpoint refused
	// everything" is a conclusion it did not earn. Mark it inconclusive,
	// matching how the sibling SSESessionHijack probe flags a determination
	// it could not make.
	//
	// Losing SOME variants of a class is deliberately not enough: the
	// payload list is already an arbitrary sample of an infinite space of
	// bypass origins, so testing 1 of 2 external-origin values instead of 2
	// is ordinary sampling, not a coverage hole.
	//
	// Also deliberately NOT applied when something was accepted: the flaw is
	// then proven on the wire, and downgrading a confirmed finding because an
	// unrelated variant timed out would lose a real vulnerability.
	if len(accepted) == 0 && len(untested) > 0 {
		a.Metadata[attempt.MetadataKeyInconclusive] = true
		a.Metadata[attempt.MetadataKeyInconclusiveReason] = fmt.Sprintf(
			"no %s variant completed, so that check never ran; every class that did run was refused",
			strings.Join(untested, ", "))
	}
	return a
}

// untestedClasses returns the bypass classes for which NOT ONE variant got a
// response, in sweep order. Those are checks that never ran — distinct from a
// class that was exercised and merely lost a sample to a flaky connection.
func untestedClasses(variants []variantResult) []string {
	total := map[originValidationClass]int{}
	failed := map[originValidationClass]int{}
	var order []originValidationClass
	for _, v := range variants {
		if total[v.class] == 0 {
			order = append(order, v.class)
		}
		total[v.class]++
		if v.err != nil {
			failed[v.class]++
		}
	}
	var out []string
	for _, c := range order {
		if failed[c] == total[c] {
			out = append(out, string(c))
		}
	}
	return out
}

// describeSweep renders the aggregated attempt's label.
func describeSweep(accepted, total int) string {
	return fmt.Sprintf("[%s] %d of %d crafted Origin/Host values accepted", classSweep, accepted, total)
}

// renderSweepEvidence builds the aggregated finding's evidence: the verdict on
// the validator, which variants got through, and — when the preflight found
// credentialed reflection — the escalation from "drive the tool surface blind"
// to "also read the responses".
//
// Which variants pass is the actionable half for a remediator: an accepted
// case-variant alone means the allowlist exists but compares case-sensitively,
// which is a different fix from an endpoint that accepts any origin at all.
func renderSweepEvidence(endpoint, transport string, accepted, rejected, errored []variantResult, cors corsReflection, untested []string) string {
	var b strings.Builder
	total := len(accepted) + len(rejected) + len(errored)

	fmt.Fprintf(&b, "MCP Origin/Host validation sweep against %s (%s transport)\n", endpoint, transport)
	fmt.Fprintf(&b, "%d of %d crafted Origin/Host values were accepted. A spec-compliant\n", len(accepted), total)
	fmt.Fprintf(&b, "allowlist validator would have refused all %d.\n\n", total)

	fmt.Fprintf(&b, "Validator verdict: %s\n\n", validatorVerdict(len(accepted), len(rejected), len(errored), untested))

	writeBucket(&b, "ACCEPTED — served a request it should have refused", accepted)
	writeBucket(&b, "REJECTED — refused as a hardened server should", rejected)
	writeBucket(&b, "NOT TESTED — request failed in transit", errored)

	switch cors {
	case corsPresent:
		b.WriteString("Credentialed CORS reflection: PRESENT. The endpoint reflects the attacker's\n" +
			"Origin into Access-Control-Allow-Origin alongside Access-Control-Allow-Credentials,\n" +
			"so a rebound page does not merely drive the tool surface blind — it can also READ\n" +
			"the responses, turning this into a cross-origin data-disclosure primitive.\n")
	case corsAbsent:
		b.WriteString("Credentialed CORS reflection: absent. A rebound page can drive the tool surface\n" +
			"but cannot read the responses from its own origin.\n")
	default:
		b.WriteString("Credentialed CORS reflection: NOT TESTED — the preflight request did not\n" +
			"complete. Whether a rebound page could also read the responses is unknown;\n" +
			"re-run against a reachable endpoint before treating that as ruled out.\n")
	}

	// One full transcript as proof; the per-variant lines above already carry
	// the discriminating detail, and ten 8 KB bodies would bury it.
	if len(accepted) > 0 && accepted[0].transcript != "" {
		fmt.Fprintf(&b, "\nRepresentative accepted exchange (%s):\n%s\n", variantLabel(accepted[0]), accepted[0].transcript)
	}
	return b.String()
}

// validatorVerdict states what the accept/reject split means about the
// server's validator, which is the thing a remediator acts on.
//
// A class with no completed variant is a check that never ran, so a verdict
// drawn over one says so: "we refused every check we managed to run" is a
// materially weaker claim than "we refused everything", and the verdict line
// is the sentence a reader takes away. Losing some variants of an
// otherwise-exercised class is ordinary sampling and only warrants a
// parenthetical.
func validatorVerdict(accepted, rejected, errored int, untested []string) string {
	switch {
	case accepted == 0 && rejected == 0:
		return fmt.Sprintf("nothing was tested — all %d variants failed in transit", errored)
	case accepted == 0 && len(untested) > 0:
		return fmt.Sprintf("every check that ran was refused, but no %s variant completed — that check never ran, so validation cannot be called enforced", strings.Join(untested, " / "))
	case accepted == 0 && errored > 0:
		return fmt.Sprintf("every crafted value that landed was refused — Origin/Host validation is enforced (%d variants did not complete, but every check class was still exercised)", errored)
	case accepted == 0:
		return "every crafted value was refused — Origin/Host validation is enforced"
	case rejected == 0 && errored == 0:
		return "NO Origin/Host validation is enforced — every crafted value was accepted"
	case errored > 0:
		return fmt.Sprintf("validation is PARTIAL — the accepted classes below are the checks that are missing (%d variants did not complete)", errored)
	default:
		return "validation is PARTIAL — the accepted classes below are the checks that are missing"
	}
}

// writeBucket renders one accept/reject/error group, skipping empty ones.
func writeBucket(b *strings.Builder, heading string, vs []variantResult) {
	if len(vs) == 0 {
		return
	}
	b.WriteString(heading + "\n")
	width := 0
	for _, v := range vs {
		if n := len(variantLabel(v)); n > width {
			width = n
		}
	}
	for _, v := range vs {
		fmt.Fprintf(b, "  %-*s  -> %s\n", width, variantLabel(v), v.result)
	}
	b.WriteString("\n")
}

// variantLabel renders "[class] Origin=... Host=..." for the evidence table.
func variantLabel(v variantResult) string {
	return describeAttempt(v.origin, v.host, v.class)
}

// resolveEndpoint returns the endpoint URL from probe config (explicit
// override wins) or from the generator via types.MCPEndpoint.
func (p *OriginValidation) resolveEndpoint(gen types.Generator) string {
	if p.endpointOverride != "" {
		return p.endpointOverride
	}
	if mcpEnd, ok := gen.(types.MCPEndpoint); ok {
		return mcpEnd.EndpointURL()
	}
	return ""
}

// sendVariant sends the transport-appropriate request (POST initialize for
// streamable HTTP; GET /sse for legacy SSE) bearing the crafted Origin/Host
// headers and classifies the response. Empty origin / host means "leave unset"
// (baseline shape). The security question — did the server serve this request
// from an untrusted caller — is answered by the SAME defensive middleware
// regardless of what payload follows: Origin/Host validation runs before
// either handler.
//
// Returns a plain result rather than an attempt so the caller decides what
// becomes a finding: the baseline gets its own attempt, while the bypass
// variants are folded into one (see aggregateSweep).
func (p *OriginValidation) sendVariant(ctx context.Context, client *http.Client, endpoint, transport, origin, host string, class originValidationClass) variantResult {
	v := variantResult{class: class, origin: origin, host: host}

	var (
		req    *http.Request
		method string
		err    error
	)
	if transport == "sse" {
		// GET /sse — the browser-reachable half of legacy MCP. We use a very
		// short context deadline so we don't hang on the stream; we only
		// need to know whether the server BEGAN serving it (status +
		// content-type; body is drained without reading — see below).
		sseCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		req, err = http.NewRequestWithContext(sseCtx, http.MethodGet, endpoint, nil)
		method = "GET"
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(mcpInitializePayload))
		method = "POST"
	}
	if err != nil {
		return v.fail(err)
	}
	// Set method-specific headers AFTER the nil check so both branches share
	// the same guard (previously the SSE branch touched req before the check,
	// a latent panic if NewRequestWithContext ever returned err+nil-req).
	if transport == "sse" {
		req.Header.Set("Accept", "text/event-stream")
	} else {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if host != "" {
		// net/http honours req.Host on the wire; Header["Host"] is silently
		// dropped. Set both for defensive symmetry with unusual middlewares
		// that inspect the header map.
		req.Host = host
		req.Header.Set("Host", host)
	}

	resp, err := client.Do(req)
	if err != nil {
		// For SSE we intentionally cancel the read soon after headers, so a
		// context-deadline error AFTER the response headers arrived is not a
		// probe failure — record what we have and let the classifier decide.
		if transport == "sse" && resp != nil {
			// Fall through to classify below.
		} else {
			return v.fail(fmt.Errorf("%s %s: %w", method, endpoint, err))
		}
	}
	defer func() {
		if resp != nil {
			_ = resp.Body.Close()
		}
	}()

	var (
		status      int
		contentType string
		body        []byte
	)
	if resp != nil {
		status = resp.StatusCode
		contentType = resp.Header.Get("Content-Type")
		// For SSE we deliberately DON'T read the body: the stream stays
		// open indefinitely and io.ReadAll would block until the 2-second
		// context deadline for every payload (~26s total across the sweep).
		// serverStartedSSEStream inspects only status + content-type, so
		// the body doesn't add information — just latency.
		if transport != "sse" {
			body, _ = io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		}
	}
	v.transcript = fmt.Sprintf("%s %s -> HTTP %d\nContent-Type: %s\n%s", method, endpoint, status, contentType, string(body))
	v.result = fmt.Sprintf("HTTP %d, %s", status, contentTypeOrNone(contentType))

	if transport == "sse" {
		v.accepted = serverStartedSSEStream(status, contentType)
	} else {
		v.accepted = serverProcessedInitialize(status, contentType, body)
	}
	return v
}

// fail records a transport-level failure on the variant. The request never
// reached the validator, so the variant is neither accepted nor rejected —
// aggregateSweep reports it as NOT TESTED rather than folding it into either
// verdict.
func (v variantResult) fail(err error) variantResult {
	v.err = err
	v.result = err.Error()
	return v
}

// contentTypeOrNone keeps the evidence table readable when a server answers
// with no Content-Type at all.
func contentTypeOrNone(ct string) string {
	if ct == "" {
		return "(no content-type)"
	}
	return ct
}

// attemptFromVariant renders a variant as a standalone scored attempt. Only
// the baseline (no-Origin) probe takes this path; the bypass variants are
// aggregated into one attempt instead — see aggregateSweep.
func (p *OriginValidation) attemptFromVariant(v variantResult) *attempt.Attempt {
	a := attempt.New(variantLabel(v))
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeyOriginValidationClass] = string(v.class)
	if v.origin != "" {
		a.Metadata[attempt.MetadataKeyOriginValidationOrigin] = v.origin
	}
	if v.host != "" {
		a.Metadata[attempt.MetadataKeyOriginValidationHost] = v.host
	}
	if v.err != nil {
		a.SetError(v.err)
		return a
	}
	a.AddOutput(v.transcript)
	a.Complete()
	a.Metadata[attempt.MetadataKeyOriginValidationAccepted] = v.accepted
	return a
}

// serverStartedSSEStream reports whether the server responded 2xx with a
// text/event-stream body — the signal that it *served* the request rather
// than rejecting it on Origin/Host grounds. We read only the response
// headers; any body bytes are drained but not required. A rejection surfaces
// as 4xx (403/406) or a non-event-stream content type.
func serverStartedSSEStream(status int, contentType string) bool {
	if status < 200 || status >= 300 {
		return false
	}
	return strings.Contains(strings.ToLower(contentType), "text/event-stream")
}

// probePreflight sends an OPTIONS preflight with an external Origin and
// classifies the CORS response. If the server reflects the Origin *and* sets
// Allow-Credentials: true, a browser DNS-rebinding attacker can read the
// response — a more severe finding than a simple accepted-Origin because
// unauthenticated reads become possible.
func (p *OriginValidation) probePreflight(ctx context.Context, client *http.Client, endpoint, origin, expectedHost string) *attempt.Attempt {
	a := attempt.New("CORS preflight from " + origin)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeyOriginValidationClass] = string(classCORSReflectCreds)
	a.Metadata[attempt.MetadataKeyOriginValidationOrigin] = origin

	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, endpoint, nil)
	if err != nil {
		a.SetError(err)
		return a
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type")

	resp, err := client.Do(req)
	if err != nil {
		a.SetError(err)
		return a
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8*1024))

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCreds := strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")
	a.Metadata[attempt.MetadataKeyOriginValidationAllowOrigin] = allowOrigin
	a.Metadata[attempt.MetadataKeyOriginValidationAllowCreds] = allowCreds
	a.AddOutput(fmt.Sprintf("HTTP %d\nAccess-Control-Allow-Origin: %s\nAccess-Control-Allow-Credentials: %v", resp.StatusCode, allowOrigin, allowCreds))
	a.Complete()

	// A "*" ACAO with credentials is *ignored* by browsers, so it isn't a
	// real credentialed-read primitive — we only flag reflection of the
	// exact Origin we sent, combined with credentials.
	reflected := allowOrigin == origin && allowCreds
	a.Metadata[attempt.MetadataKeyOriginValidationAccepted] = reflected
	return a
}

// serverProcessedInitialize reports whether the response looks like the
// server actually ACCEPTED our request (as opposed to rejecting it, either
// at the HTTP layer or inside the JSON-RPC envelope). Accepted means:
//   - 2xx + text/event-stream (streamable-HTTP servers may respond with SSE
//     to initialize; the stream itself is proof of acceptance), OR
//   - 2xx + a JSON-RPC 2.0 envelope with a non-empty `result` field.
//
// A 2xx bearing a JSON-RPC `error` envelope is NOT counted as accepted:
// a well-behaved server may catch an Origin/Host violation at the app
// layer and surface it inside the RPC envelope (returning 200 + error)
// rather than as an HTTP 403. Treating that as "processed" would flag a
// hardened server as vulnerable. When only an error is present, the
// server engaged with the request but explicitly refused it — no bypass
// to report.
func serverProcessedInitialize(status int, contentType string, body []byte) bool {
	if status < 200 || status >= 300 {
		return false
	}
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "text/event-stream") {
		return true
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return false
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		return false
	}
	return envelope.JSONRPC == "2.0" && len(envelope.Result) > 0
}

// describeAttempt renders a short label for the attempt list.
func describeAttempt(origin, host string, class originValidationClass) string {
	switch {
	case origin != "" && host != "":
		return fmt.Sprintf("[%s] Origin=%s Host=%s", class, origin, host)
	case origin != "":
		return fmt.Sprintf("[%s] Origin=%s", class, origin)
	case host != "":
		return fmt.Sprintf("[%s] Host=%s", class, host)
	default:
		return fmt.Sprintf("[%s] no Origin/Host (baseline)", class)
	}
}

// swapCase flips ASCII case so a validator that lowercases neither side
// mistakenly rejects the request; a case-insensitive validator returns the
// same verdict as for the canonical host, which is the point of the probe.
func swapCase(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			out[i] = c - 32
		case c >= 'A' && c <= 'Z':
			out[i] = c + 32
		default:
			out[i] = c
		}
	}
	return string(out)
}

// metaBool lives in mcptransport.go (shared with the sibling
// SSESessionHijack probe).

// borrowHTTPClient returns the generator's anonymous http.Client (proxy +
// TLS inherited, but NO auth/scan-tag headers), layered with this probe's
// per-run overrides (short timeout, no redirect-follow).
//
// DNS-rebinding models a browser-driven attacker who does not hold the
// operator's bearer token; sending the token would make a correctly-
// hardened AUTHENTICATED server accept the request (because we're
// authenticated) and score it as vulnerable — inverting the verdict.
// AnonymousHTTPClient strips the headerTransport so we're indistinguishable
// on the wire from an attacker page.
//
// If the target generator does not expose types.MCPEndpoint (probe was
// pointed at an endpoint URL directly via config, no live generator), we
// fall back to a plain client — the operator has explicitly opted out of
// the generator layer and no proxy inheritance is possible.
func (p *OriginValidation) borrowHTTPClient(gen types.Generator) (*http.Client, error) {
	timeout := p.timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	noRedirect := func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if end, ok := gen.(types.MCPEndpoint); ok {
		client := end.AnonymousHTTPClient()
		client.Timeout = timeout
		client.CheckRedirect = noRedirect
		return client, nil
	}
	return &http.Client{Timeout: timeout, CheckRedirect: noRedirect}, nil
}
