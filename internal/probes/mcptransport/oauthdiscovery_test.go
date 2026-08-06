package mcptransport

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// discoveryServer serves a configurable set of the spec-defined signals.
func discoveryServer(t *testing.T, challenge string, docs map[string]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for path, body := range docs {
		b := body
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(b))
		})
	}
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, _ *http.Request) {
		if challenge != "" {
			w.Header().Set("WWW-Authenticate", challenge)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestDiscoverOAuthProtection_SpecDefinedSignals(t *testing.T) {
	t.Run("protected-resource metadata naming this endpoint", func(t *testing.T) {
		// The `resource` member must COVER the endpoint under test, so the document
		// has to be built against the live server's own URL.
		var srv *httptest.Server
		mux := http.NewServeMux()
		mux.HandleFunc(protectedResourcePath, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"resource":%q,"authorization_servers":["https://as.example.com"]}`, srv.URL)
		})
		mux.HandleFunc("/mcp", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		srv = httptest.NewServer(mux)
		t.Cleanup(srv.Close)

		if !discoverOAuthProtection(context.Background(), srv.Client(), srv.URL+"/mcp").declared() {
			t.Fatal("protected-resource metadata naming this endpoint was not recognised as a declaration")
		}
	})

	t.Run("www-authenticate challenge on 401", func(t *testing.T) {
		srv := discoveryServer(t, `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"`, nil)
		d := discoverOAuthProtection(context.Background(), srv.Client(), srv.URL+"/mcp")
		if !d.declared() {
			t.Fatal("WWW-Authenticate challenge was not recognised as a declaration")
		}
		if d.challenge == "" {
			t.Error("challenge value not captured for the report")
		}
	})
}

// TestDiscoverOAuthProtection_RequiresResourceBinding covers the false-positive path
// that scores most aggressively: the declared-open class reaches 1.0 without
// operator credentials and without the loopback softening every other class gets.
//
// Presence of an OAuth metadata document at an origin says only that SOMETHING
// there speaks OAuth — a co-hosted application, an unrelated API, a shared reverse
// proxy. It is not a statement that THIS MCP endpoint is protected.
func TestDiscoverOAuthProtection_RequiresResourceBinding(t *testing.T) {
	t.Run("protected-resource metadata naming a different resource", func(t *testing.T) {
		srv := discoveryServer(t, "", map[string]string{
			protectedResourcePath: `{"resource":"https://someone-elses-api.example.com","authorization_servers":["https://as.example.com"]}`,
		})
		if discoverOAuthProtection(context.Background(), srv.Client(), srv.URL+"/mcp").declared() {
			t.Error("metadata about a DIFFERENT resource was read as a declaration about this endpoint")
		}
	})

	t.Run("authorization-server metadata alone is not a declaration", func(t *testing.T) {
		// An authorization server co-hosted with an unguarded MCP endpoint is a
		// perfectly ordinary deployment. RFC 8414 metadata describes the AS, never
		// the protection status of a particular resource.
		srv := discoveryServer(t, "", map[string]string{
			authServerPath: `{"issuer":"https://as.example.com","token_endpoint":"https://as.example.com/token"}`,
		})
		if discoverOAuthProtection(context.Background(), srv.Client(), srv.URL+"/mcp").declared() {
			t.Error("authorization-server metadata alone was read as a declaration about this endpoint")
		}
	})

	t.Run("resource covering the origin covers a path beneath it", func(t *testing.T) {
		var srv *httptest.Server
		mux := http.NewServeMux()
		mux.HandleFunc(protectedResourcePath, func(w http.ResponseWriter, _ *http.Request) {
			// Names the ORIGIN, so every path beneath it is declared protected.
			_, _ = fmt.Fprintf(w, `{"resource":%q}`, srv.URL)
		})
		srv = httptest.NewServer(mux)
		t.Cleanup(srv.Close)

		if !discoverOAuthProtection(context.Background(), srv.Client(), srv.URL+"/deep/mcp").declared() {
			t.Error("a resource naming the origin did not cover a path beneath it")
		}
	})
}

func TestDiscoverOAuthProtection_FalsePositiveGuards(t *testing.T) {
	t.Run("plain server declares nothing", func(t *testing.T) {
		srv := discoveryServer(t, "", nil)
		if discoverOAuthProtection(context.Background(), srv.Client(), srv.URL+"/mcp").declared() {
			t.Error("a server publishing nothing was read as authorization-gated")
		}
	})

	t.Run("catch-all router answering 200 for every path", func(t *testing.T) {
		// A single-page app or permissive router returns 200 with a body for any
		// path. A status code alone must not be read as a metadata document.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`<!doctype html><title>app</title>`))
		}))
		t.Cleanup(srv.Close)
		if discoverOAuthProtection(context.Background(), srv.Client(), srv.URL+"/mcp").declared() {
			t.Error("catch-all 200 was mistaken for OAuth metadata")
		}
	})

	t.Run("json without a required field", func(t *testing.T) {
		// Valid JSON at the right path, but neither RFC's required field. Not a
		// metadata document.
		srv := discoveryServer(t, "", map[string]string{
			protectedResourcePath: `{"note":"not oauth metadata"}`,
		})
		if discoverOAuthProtection(context.Background(), srv.Client(), srv.URL+"/mcp").declared() {
			t.Error("unrelated JSON was mistaken for OAuth metadata")
		}
	})

	t.Run("www-authenticate on a 200 is not a challenge", func(t *testing.T) {
		// The header only means "credentials required" alongside a refusal status.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(srv.Close)
		if discoverOAuthProtection(context.Background(), srv.Client(), srv.URL+"/mcp").declared() {
			t.Error("WWW-Authenticate alongside a 200 was treated as a refusal")
		}
	})

	t.Run("nil client and empty endpoint are safe", func(t *testing.T) {
		if discoverOAuthProtection(context.Background(), nil, "http://x/mcp").declared() {
			t.Error("nil client produced a declaration")
		}
		if discoverOAuthProtection(context.Background(), http.DefaultClient, "").declared() {
			t.Error("empty endpoint produced a declaration")
		}
	})
}

// TestDiscoverOAuthProtection_StreamingEndpointDoesNotHang is the regression for a
// hang found only by running the probe against a live legacy HTTP+SSE target.
//
// Discovery step 1 GETs the MCP endpoint to look for a WWW-Authenticate challenge.
// On an SSE-transport server that GET does not return a document — it opens an
// event stream that stays open for the life of the session. Draining that body to
// a byte cap blocks until enough keepalive bytes arrive to fill the cap, so the
// probe hung indefinitely and emitted nothing at all. A byte cap bounds SIZE, not
// TIME; only a deadline bounds time.
//
// The server here models a real SSE MCP target exactly: an endless event stream at
// the endpoint, 404 at the well-known paths. The assertion is a tight latency
// bound, because that is what distinguishes "closes the body unread" from "waits
// out a deadline it should never have reached".
func TestDiscoverOAuthProtection_StreamingEndpointDoesNotHang(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		// A wall-clock cap as well as the request context: if the assertion below
		// fails, t.Fatal runs while this handler is still writing and srv.Close in
		// the cleanup would wait on the outstanding request.
		deadline := time.After(3 * discoveryTimeout)
		for {
			select {
			case <-r.Context().Done():
				return
			case <-deadline:
				return
			case <-time.After(10 * time.Millisecond):
				_, _ = w.Write([]byte(": keepalive\n\n"))
				if flusher != nil {
					flusher.Flush()
				}
			}
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	type result struct {
		d       oauthDeclaration
		elapsed time.Duration
	}
	done := make(chan result, 1)
	go func() {
		start := time.Now()
		d := discoverOAuthProtection(context.Background(), srv.Client(), srv.URL+"/sse")
		done <- result{d, time.Since(start)}
	}()

	select {
	case got := <-done:
		// A streaming server that publishes no metadata has declared nothing.
		if got.d.declared() {
			t.Error("a server that streams keepalives and publishes no metadata was read as authorization-gated")
		}
		// Well inside discoveryTimeout: reaching the deadline would mean the body
		// is still being read rather than closed.
		if got.elapsed > 2*time.Second {
			t.Errorf("discovery took %v against a never-ending stream; the endpoint probe must close the body unread, not wait out its deadline", got.elapsed)
		}
	case <-time.After(2 * discoveryTimeout):
		t.Fatal("discoverOAuthProtection never returned against a never-ending response stream; a byte cap bounds size, not time")
	}
}
