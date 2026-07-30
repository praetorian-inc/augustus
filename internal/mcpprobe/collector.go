package mcpprobe

import (
	"fmt"
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
type Collector struct {
	base   string
	marker string
	srv    *http.Server

	mu   sync.Mutex
	hits map[string]bool
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
		hits:   make(map[string]bool),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/oob/", func(w http.ResponseWriter, r *http.Request) {
		token := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/oob/"), "/", 2)[0]
		if token != "" {
			c.mu.Lock()
			c.hits[token] = true
			c.mu.Unlock()
		}
		_, _ = w.Write([]byte(c.marker))
	})

	c.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = c.srv.Serve(ln) }()
	return c, nil
}

// URL returns the canary URL for a token.
func (c *Collector) URL(token string) string { return c.base + "/oob/" + token }

// WasHit reports whether a callback for token was received.
func (c *Collector) WasHit(token string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits[token]
}

// Close stops the collector.
func (c *Collector) Close() { _ = c.srv.Close() }
