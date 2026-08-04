package mcpprobe

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Collector is a built-in out-of-band interaction listener. A probe injects URLs
// that point at it; a target that fetches such a URL triggers a recorded
// callback, confirming the sink reached the network even when it returns nothing
// to the client (the blind case). Every response also carries a body marker so a
// sink that DOES return the fetched content can be caught by reflection as a
// second signal.
//
// Deployment note: against a REMOTE target the collector must be reachable from
// that target, so the loopback default will not receive callbacks. Prefer setting
// oob_base_url to a controlled redirector you own and that forwards to this
// listener, rather than binding oob_listen to a public interface — exposing a raw
// port on the scanner host puts an unauthenticated listener on the network. A
// non-loopback bind is warned about at start-up.
type Collector struct {
	base   string
	marker string
	srv    *http.Server

	mu sync.Mutex
	// known holds the tokens this collector actually issued; hits holds the subset
	// that were called back. Recording only issued tokens keeps the map bounded on a
	// network-reachable listener and stops the collector logging callbacks it never
	// asked for — anyone can probe /oob/<anything>.
	known map[string]bool
	hits  map[string]bool
}

// StartCollector binds an HTTP listener and starts serving. listen is the bind
// address (host:port; "127.0.0.1:0" for an ephemeral port). baseOverride, when
// set, is the URL the *target* should use to reach the collector (for targets
// that cannot reach the bind address directly, e.g. via a tunnel); otherwise the
// base is derived from the actual listen address.
func StartCollector(listen, baseOverride, marker string) (*Collector, error) {
	if listen == "" {
		listen = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("mcpprobe: OOB collector listen on %q: %w", listen, err)
	}

	base := baseOverride
	if base == "" {
		base = "http://" + ln.Addr().String()
	}
	base = strings.TrimRight(base, "/")

	c := &Collector{
		base:   base,
		marker: marker,
		known:  make(map[string]bool),
		hits:   make(map[string]bool),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/oob/", func(w http.ResponseWriter, r *http.Request) {
		token := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/oob/"), "/", 2)[0]
		if token != "" {
			c.mu.Lock()
			if c.known[token] {
				c.hits[token] = true
			}
			c.mu.Unlock()
		}
		// Answer regardless, so a genuine fetcher still sees the marker (and an
		// unknown token learns nothing about which tokens are tracked).
		_, _ = w.Write([]byte(c.marker))
	})

	if tcp, ok := ln.Addr().(*net.TCPAddr); ok && !tcp.IP.IsLoopback() {
		slog.Warn("mcpprobe: out-of-band collector bound to a non-loopback address and is reachable from the network; "+
			"prefer oob_base_url pointing at a controlled redirector over exposing a port on the scanner host",
			"addr", ln.Addr().String())
	}

	// Full timeouts, not just the header one: this listener can be reachable from
	// the network, so a slow or idle peer must not hold a connection open. The
	// header cap also bounds the token/URL length an unknown caller can send.
	c.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	go func() { _ = c.srv.Serve(ln) }()
	return c, nil
}

// URL returns the canary URL for a token and records the token as issued. Every
// tracked token reaches the target through this method, so registering here is
// what lets the handler ignore callbacks for tokens the collector never handed out.
//
// It also tightens ShellProofURL: a sink that fetches the literal "…$()…" path
// instead of executing it requests a token that was never issued, so the hit is
// discarded rather than stored.
func (c *Collector) URL(token string) string {
	c.mu.Lock()
	c.known[token] = true
	c.mu.Unlock()
	return c.base + "/oob/" + token
}

// WasHit reports whether a callback for token was received.
func (c *Collector) WasHit(token string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits[token]
}

// Close stops the collector.
func (c *Collector) Close() { _ = c.srv.Close() }
