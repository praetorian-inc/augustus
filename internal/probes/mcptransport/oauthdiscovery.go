package mcptransport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// Spec-defined discovery documents. A server publishing either one is declaring
// that access to it is authorization-gated.
//
//	RFC 9728 — OAuth 2.0 Protected Resource Metadata
//	RFC 8414 — OAuth 2.0 Authorization Server Metadata
//
// The MCP authorization specification builds directly on both: a server that
// requires authorization answers 401 with a WWW-Authenticate challenge pointing
// at its protected-resource metadata.
const (
	protectedResourcePath = "/.well-known/oauth-protected-resource"
	authServerPath        = "/.well-known/oauth-authorization-server"
)

// maxDiscoveryBody caps what we read from a discovery document. These are small
// JSON objects by specification; the cap keeps a hostile or misconfigured host
// from streaming indefinitely into a probe that only needs a couple of fields.
const maxDiscoveryBody = 64 << 10

// discoveryTimeout bounds EACH discovery request independently.
//
// A byte cap alone does not bound the work: a host that answers and then trickles
// bytes (or never sends any) stalls a capped read just as effectively as an
// unbounded one. Discovery is a preflight step whose whole output is "did the
// target declare authorization?", so a slow or streaming host must yield "no
// declaration" quickly rather than stall the scan behind it.
const discoveryTimeout = 10 * time.Second

// oauthDeclaration records the ways a target declared itself an authorization-
// gated resource. Any one of them is the SERVER'S OWN statement that credentials
// are required, which is why a declaration can stand in for operator-supplied
// credentials as evidence of intent.
//
// This matters because of a gap that cannot otherwise be closed: scanning a
// target nobody handed us a token for, "the anonymous session worked" is
// uninterpretable — public-by-design and catastrophically-open look identical on
// the wire. A server that publishes one of these documents has told us which of
// the two it is, with no guessing and no heuristics.
type oauthDeclaration struct {
	// challenge is the WWW-Authenticate value returned for an unauthenticated
	// request, when the endpoint challenged rather than serving.
	challenge string
	// documents are the spec-defined discovery URLs found to exist.
	documents []string
}

// declared reports whether the target stated that it is authorization-gated.
func (d oauthDeclaration) declared() bool {
	return d.challenge != "" || len(d.documents) > 0
}

// evidence renders the declaration for a report. Only what the server itself
// returned, so a reviewer can re-fetch and confirm.
func (d oauthDeclaration) evidence() string {
	var parts []string
	if d.challenge != "" {
		parts = append(parts, "WWW-Authenticate: "+d.challenge)
	}
	for _, doc := range d.documents {
		parts = append(parts, "published "+doc)
	}
	return strings.Join(parts, "; ")
}

// discoverOAuthProtection asks the target whether it considers itself an
// authorization-gated MCP resource, using ONLY mechanisms the specifications
// define. There is no wordlist, no path guessing and no interpretation of prose:
// every signal is either a standard header or a standard document at a standard
// path.
//
// All requests go through the caller's anonymous client, so the generator's proxy
// and TLS settings are inherited while no credentials are sent — the whole point
// is to observe how the target treats a caller who holds nothing.
//
// Failure is silent: a target that publishes nothing simply yields an empty
// declaration, which reads as "no evidence either way" rather than as absence of
// authorization.
func discoverOAuthProtection(ctx context.Context, client *http.Client, endpoint string) oauthDeclaration {
	var d oauthDeclaration
	if client == nil || endpoint == "" {
		return d
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return d
	}

	// 1. Does the endpoint itself challenge an unauthenticated caller? A
	//    WWW-Authenticate header is the server refusing and naming its scheme.
	//
	//    The body is CLOSED UNREAD. Only the status line and one header carry the
	//    signal here, and draining the rest is not merely wasted work: on a legacy
	//    HTTP+SSE target this GET opens an event stream that never ends, so a
	//    read-to-cap blocks until enough keepalive bytes trickle in to fill the
	//    cap — in practice, forever. Measured against a live SSE-transport server:
	//    the probe hung indefinitely and emitted nothing at all, which in a hosted
	//    capability is worse than any wrong verdict.
	reqCtx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	if req, reqErr := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil); reqErr == nil {
		if resp, doErr := client.Do(req); doErr == nil {
			challenge := resp.Header.Get("WWW-Authenticate")
			_ = resp.Body.Close()
			if challenge != "" && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
				d.challenge = challenge
			}
		}
	}

	// 2. Does the target publish RFC 9728 protected-resource metadata for THIS
	//    resource?
	//
	//    Both spec-defined locations are probed, and the document must name the
	//    resource identifier that the location it was fetched from implies:
	//
	//      https://h/mcp -> https://h/.well-known/oauth-protected-resource/mcp
	//                       (RFC 9728 sec 3.1 inserts the well-known segment
	//                        between host and path) and must declare https://h/mcp
	//      https://h     -> https://h/.well-known/oauth-protected-resource
	//                       and must declare https://h
	//
	//    Probing only the origin-level document missed a server that correctly
	//    publishes the path-scoped one, which read as "no declaration" and skipped
	//    the check entirely. Accepting a resource value that merely PREFIXES the
	//    endpoint was the opposite error: RFC 9728 sec 3.3 requires the value to be
	//    the resource identifier itself, and a document describing the origin is
	//    evidence about the origin, not about a path mounted beneath it. That
	//    matters because this class scores 1.0 while bypassing both the
	//    configured-credentials precondition and the loopback softening, so the
	//    weakest evidence reaches the strongest verdict.
	for _, cand := range protectedResourceLocations(u) {
		if fetchProtectedResourceDoc(ctx, client, cand.url, cand.resource) {
			d.documents = append(d.documents, cand.url)
			break
		}
	}

	// RFC 8414 authorization-server metadata is deliberately NOT accepted on its
	// own. It describes an authorization SERVER, not the protection status of any
	// particular resource: a host can run an AS and serve an entirely unguarded MCP
	// endpoint beside it. Recorded only as corroboration for a declaration already
	// established above.
	if len(d.documents) > 0 {
		origin := u.Scheme + "://" + u.Host
		if fetchDiscoveryDoc(ctx, client, origin+authServerPath) {
			d.documents = append(d.documents, origin+authServerPath)
		}
	}
	return d
}

// probeDeclaredOpen runs the credential-free session against a target that has
// declared itself authorization-gated, and scores the outcome on the strength of
// that declaration alone.
//
// No authenticated control is issued here, and none is needed: the control's job
// is to establish that credentials are expected, and the server has already said
// so publicly. Attempting one would be meaningless anyway, since we hold no
// credentials to authenticate with.
func (p *UnauthenticatedAccess) probeDeclaredOpen(ctx context.Context, end types.MCPEndpoint, endpoint string, u *url.URL, oauth oauthDeclaration) ([]*attempt.Attempt, error) {
	targetClass := classifyTargetHost(ctx, u.Host)
	slog.Info("mcptransport.UnauthenticatedAccess: target declares itself authorization-gated; assessing the credential-free session against that declaration",
		"endpoint", endpoint, "class", string(targetClass), "declaration", oauth.evidence())

	a := attempt.New("anonymous session against a target that publicly declares itself authorization-gated: " + oauth.evidence())
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[mcpprobe.MetaAuthClass] = mcpprobe.AuthClassOAuthDeclaredOpen
	a.Metadata[mcpprobe.MetaAuthTargetClass] = string(targetClass)
	// Accurately false: the verdict rests on the target's declaration, not on
	// anything the operator supplied.
	a.Metadata[mcpprobe.MetaAuthCredentialsConfigured] = false
	a.Metadata[mcpprobe.MetaAuthOAuthDeclaration] = oauth.evidence()

	sess, err := mcpprobe.ConnectAnonymous(ctx, end, p.timeout)
	if err != nil {
		// The declaration is honoured: it said credentials are required and it
		// refused us. Recorded as evidence rather than dropped, so "refused" stays
		// distinguishable from "never asked".
		a.Metadata[mcpprobe.MetaAuthAnonymousSucceeded] = false
		a.AddOutput("target refused the credential-free session, consistent with its own declaration: " + err.Error())
		a.Complete()
		return []*attempt.Attempt{a}, nil
	}
	defer sess.Close()

	tools, listErr := sess.ListTools(ctx)
	anonOK := listErr == nil || errors.Is(listErr, types.ErrCatalogTruncated)
	a.Metadata[mcpprobe.MetaAuthAnonymousSucceeded] = anonOK
	if !anonOK {
		a.AddOutput("credential-free session initialized but tools/list was refused: " + listErr.Error())
		a.Complete()
		return []*attempt.Attempt{a}, nil
	}
	a.AddOutput(fmt.Sprintf("credential-free tools/list returned %d tool(s) from a target that declares authorization is required (%s)",
		len(tools), oauth.evidence()))
	a.Complete()
	return []*attempt.Attempt{a}, nil
}

// fetchProtectedResourceDoc reports whether the URL serves RFC 9728
// protected-resource metadata that covers the endpoint under test.
//
// RFC 9728 requires a "resource" member identifying the resource the document
// describes. It is compared against the endpoint rather than merely required to
// exist: a document naming a DIFFERENT resource is evidence about that other
// resource, not this one.
//
// The comparison is an EXACT match on the resource identifier (scheme + host +
// path, modulo a trailing slash and case; see sameResourceIdentifier), because
// RFC 9728 requires the document to name the SAME resource. So an endpoint at
// https://h/mcp is covered only by a document naming https://h/mcp — not by one
// naming https://h or https://h/other. (An earlier prefix match accepted any
// protected-resource document on the same origin, a false positive; do not
// restore it.)
func fetchProtectedResourceDoc(ctx context.Context, client *http.Client, docURL, expectedResource string) bool {
	doc, ok := fetchJSONDoc(ctx, client, docURL)
	if !ok {
		return false
	}
	resource, _ := doc["resource"].(string)
	if resource == "" {
		return false
	}
	if !sameResourceIdentifier(resource, expectedResource) {
		slog.Info("mcptransport.UnauthenticatedAccess: protected-resource metadata names a different resource, so it is not a declaration about this endpoint",
			"declared_resource", resource, "expected_resource", expectedResource, "document", docURL)
		return false
	}
	return true
}

// resourceLocation pairs a spec-defined metadata URL with the resource identifier
// a document served there must declare.
type resourceLocation struct {
	url      string
	resource string
}

// protectedResourceLocations returns the RFC 9728 metadata locations for an
// endpoint, most specific first.
//
// Section 3.1 forms the URL by inserting the well-known segment between the host
// and the resource path, so an endpoint at /mcp has its own document distinct from
// the origin's. Both are tried because either can be the correct one depending on
// what the deployment treats as the resource, and each carries a different expected
// identifier.
func protectedResourceLocations(u *url.URL) []resourceLocation {
	origin := u.Scheme + "://" + u.Host
	out := make([]resourceLocation, 0, 2)
	if p := strings.TrimSuffix(u.Path, "/"); p != "" {
		out = append(out, resourceLocation{
			url:      origin + protectedResourcePath + p,
			resource: origin + p,
		})
	}
	return append(out, resourceLocation{url: origin + protectedResourcePath, resource: origin})
}

// sameResourceIdentifier compares a declared resource value against the identifier
// its location implies. RFC 9728 requires them to be the same resource, so the
// comparison is exact apart from a trailing slash and case-insensitive scheme/host.
func sameResourceIdentifier(declared, expected string) bool {
	d, err := url.Parse(strings.TrimSuffix(declared, "/"))
	if err != nil {
		return false
	}
	e, err := url.Parse(strings.TrimSuffix(expected, "/"))
	if err != nil {
		return false
	}
	return strings.EqualFold(d.Scheme, e.Scheme) &&
		strings.EqualFold(d.Host, e.Host) &&
		strings.TrimSuffix(d.Path, "/") == strings.TrimSuffix(e.Path, "/")
}

// fetchJSONDoc retrieves a bounded JSON object from a discovery URL.
func fetchJSONDoc(ctx context.Context, client *http.Client, docURL string) (map[string]any, bool) {
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return nil, false
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBody))
	if err != nil {
		return nil, false
	}
	var doc map[string]any
	if json.Unmarshal(body, &doc) != nil {
		return nil, false
	}
	return doc, true
}

// fetchDiscoveryDoc reports whether a URL serves a plausible OAuth metadata
// document. A required field must be present: a 200 alone is not enough, because
// single-page apps and catch-all routers answer 200 for any path.
func fetchDiscoveryDoc(ctx context.Context, client *http.Client, docURL string) bool {
	// Bounded independently of the caller's context: the byte cap below limits how
	// much is read, never how long the read waits, so a host that streams slowly
	// or stalls mid-body would otherwise hold the scan open indefinitely.
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBody))
	if err != nil {
		return false
	}
	var doc map[string]any
	if json.Unmarshal(body, &doc) != nil {
		return false
	}
	// RFC 9728 requires "resource"; RFC 8414 requires "issuer". Either identifies
	// a genuine metadata document rather than an incidental 200.
	for _, required := range []string{"resource", "issuer", "authorization_servers"} {
		if _, ok := doc[required]; ok {
			return true
		}
	}
	return false
}
