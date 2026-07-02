// Package wsutil holds WebSocket transport and JSON-field helpers shared by the
// websocket generators (the plain websocket.Websocket duplex generator and the
// hybrid.Hybrid HTTP+WebSocket choreography generator). It exists so neither
// generator has to duplicate connection setup, frame bookkeeping, or the small
// JSONPath subset used to pull text out of response frames.
package wsutil

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpproxy"
	"golang.org/x/net/websocket"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// EnvProxyFor resolves which proxy to use for a ws/wss target. An explicit proxy
// (non-nil) always wins; otherwise the standard HTTP_PROXY/HTTPS_PROXY/NO_PROXY
// environment is consulted — so a single external `HTTPS_PROXY=...` toggles Burp
// for every leg without per-generator config. ws->http and wss->https are mapped
// so HTTPS_PROXY applies to secure WebSockets. Returns nil for a direct dial.
func EnvProxyFor(rawURL string, explicit *url.URL) (*url.URL, error) {
	if explicit != nil {
		return explicit, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("websocket: parse target url %q: %w", rawURL, err)
	}
	probe := *u
	switch u.Scheme {
	case "wss":
		probe.Scheme = "https"
	case "ws":
		probe.Scheme = "http"
	}
	return httpproxy.FromEnvironment().ProxyFunc()(&probe)
}

// DialViaProxy opens a WebSocket through an HTTP CONNECT proxy (e.g. Burp). It
// tunnels to the target host with CONNECT, performs the TLS handshake for wss
// targets over the tunnel, then runs the WebSocket handshake on the tunneled
// connection. Reads of the CONNECT response are byte-bounded so no application
// bytes are consumed before the TLS/WS handshake takes over the socket.
func DialViaProxy(ctx context.Context, wsCfg *websocket.Config, proxyURL *url.URL) (*websocket.Conn, error) {
	target := wsCfg.Location
	hostport := target.Host
	if !strings.Contains(hostport, ":") {
		if target.Scheme == "wss" {
			hostport += ":443"
		} else {
			hostport += ":80"
		}
	}

	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("websocket: dial proxy %s: %w", proxyURL.Host, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostport, hostport)
	if _, err := raw.Write([]byte(connectReq)); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("websocket: write CONNECT: %w", err)
	}

	status, err := readCONNECTStatus(raw)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("websocket: read CONNECT response: %w", err)
	}
	if !connectSucceeded(status) {
		_ = raw.Close()
		return nil, fmt.Errorf("websocket: proxy CONNECT failed: %q", status)
	}

	var rwc io.ReadWriteCloser = raw
	if target.Scheme == "wss" {
		tlsCfg := wsCfg.TlsConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		tlsCfg = tlsCfg.Clone()
		if tlsCfg.ServerName == "" {
			tlsCfg.ServerName = target.Hostname()
		}
		tlsConn := tls.Client(raw, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("websocket: TLS handshake via proxy: %w", err)
		}
		rwc = tlsConn
	}

	// Keep the context deadline active across the WebSocket upgrade handshake —
	// NewClient performs blocking network I/O, so clearing the deadline first
	// would let a stalled proxy/server hang past the request timeout.
	conn, err := websocket.NewClient(wsCfg, rwc)
	if err != nil {
		_ = rwc.Close()
		return nil, fmt.Errorf("websocket: client handshake via proxy: %w", err)
	}
	_ = raw.SetDeadline(time.Time{}) // clear handshake deadline; per-frame deadlines apply later
	return conn, nil
}

// connectSucceeded reports whether a proxy CONNECT status line indicates a 200
// tunnel. The status code token is matched exactly — a substring check for
// " 200" would wrongly accept lines like "HTTP/1.1 407 Proxy ... 200".
func connectSucceeded(statusLine string) bool {
	fields := strings.Fields(statusLine)
	return len(fields) >= 2 && fields[1] == "200"
}

// readCONNECTStatus reads the proxy's CONNECT response one byte at a time up to
// the end of the header block, returning the status line. Byte-bounded reading
// guarantees the reader never consumes bytes belonging to the subsequent TLS or
// WebSocket handshake.
func readCONNECTStatus(c net.Conn) (string, error) {
	var buf []byte
	tmp := make([]byte, 1)
	for {
		n, err := c.Read(tmp)
		if err != nil {
			return "", err
		}
		if n > 0 {
			buf = append(buf, tmp[0])
			if bytes.HasSuffix(buf, []byte("\r\n\r\n")) {
				break
			}
		}
		if len(buf) > 16*1024 {
			return "", errors.New("CONNECT response headers too large")
		}
	}
	line := string(buf)
	if i := strings.Index(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	return line, nil
}

// MaxFrameBytes caps a single inbound frame to prevent OOM from a malicious or
// runaway endpoint. Mirrors the REST generator's 10MB response cap.
const MaxFrameBytes = 10 * 1024 * 1024

// BuildHandshakeConfig assembles the websocket.Config used for a dial. Origin is
// auto-derived from the target URL when not explicitly configured, because
// x/net/websocket requires a valid origin and non-browser clients rarely need a
// specific one.
func BuildHandshakeConfig(uri, origin string, headers map[string]string, subprotocols []string, insecure bool) (*websocket.Config, error) {
	loc, err := url.ParseRequestURI(uri)
	if err != nil {
		return nil, fmt.Errorf("websocket: invalid uri %q: %w", uri, err)
	}
	if loc.Scheme != "ws" && loc.Scheme != "wss" {
		return nil, fmt.Errorf("websocket: uri scheme must be ws or wss, got %q", loc.Scheme)
	}

	if origin == "" {
		origin = deriveOrigin(loc)
	}

	wsCfg, err := websocket.NewConfig(uri, origin)
	if err != nil {
		return nil, fmt.Errorf("websocket: build config: %w", err)
	}

	for k, v := range headers {
		wsCfg.Header.Set(k, v)
	}
	if len(subprotocols) > 0 {
		wsCfg.Protocol = subprotocols
	}
	if loc.Scheme == "wss" {
		if insecure {
			slog.Warn("websocket: TLS certificate verification disabled (insecure_skip_verify=true)", "target", uri)
		}
		// #nosec G402 -- InsecureSkipVerify is opt-in via insecure_skip_verify; targets are operator-chosen test endpoints
		wsCfg.TlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure}
	}
	return wsCfg, nil
}

// deriveOrigin maps a ws/wss target URL to a plausible http/https origin.
func deriveOrigin(loc *url.URL) string {
	scheme := "http"
	if loc.Scheme == "wss" {
		scheme = "https"
	}
	return scheme + "://" + loc.Host
}

// IsTimeout reports whether err is a network timeout (an idle read deadline).
func IsTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// JoinRaw concatenates accumulated frame payloads with newlines so the raw
// record stays readable for hooks while preserving frame boundaries.
func JoinRaw(parts [][]byte) []byte {
	if len(parts) == 0 {
		return nil
	}
	if len(parts) == 1 {
		return parts[0]
	}
	sep := []byte("\n")
	total := 0
	for _, p := range parts {
		total += len(p) + len(sep)
	}
	out := make([]byte, 0, total)
	for i, p := range parts {
		if i > 0 {
			out = append(out, sep...)
		}
		out = append(out, p...)
	}
	return out
}

// DurationSeconds reads a numeric config value expressed in seconds, accepting
// both float64 (JSON) and int. The bool result reports whether the key was set.
func DurationSeconds(m registry.Config, key string) (time.Duration, bool) {
	switch v := m[key].(type) {
	case float64:
		return time.Duration(v * float64(time.Second)), true
	case int:
		return time.Duration(v) * time.Second, true
	default:
		return 0, false
	}
}

// JSONEscape escapes a string for safe insertion inside a JSON string value
// (returns the contents without the surrounding quotes).
func JSONEscape(s string) string {
	data, err := json.Marshal(s)
	if err != nil {
		return s
	}
	return string(data[1 : len(data)-1])
}

// ExtractField parses frame as JSON and returns the value at path. The path is a
// dotted field expression with optional array indices and an optional leading
// "$" (JSONPath-style), e.g. "data.text", "$.choices[0].message.content". This
// is a deliberately small subset that covers the response shapes WebSocket
// chat/agent endpoints actually emit.
func ExtractField(frame []byte, path string) (string, error) {
	var data any
	if err := json.Unmarshal(frame, &data); err != nil {
		return "", fmt.Errorf("websocket: parse JSON frame: %w", err)
	}

	current := data
	for _, seg := range parsePath(path) {
		next, err := navigate(current, seg)
		if err != nil {
			return "", err
		}
		current = next
	}
	return valueToString(current), nil
}

// ExtractFirst returns the first path that resolves to a non-empty value.
func ExtractFirst(frame []byte, paths []string) (string, bool) {
	for _, p := range paths {
		if val, err := ExtractField(frame, p); err == nil && val != "" {
			return val, true
		}
	}
	return "", false
}

// parsePath splits a field path into ordered segments. Field names become bare
// strings; array indices become "[N]" segments.
func parsePath(path string) []string {
	path = strings.TrimPrefix(path, "$")
	var segments []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			segments = append(segments, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(path); i++ {
		switch c := path[i]; c {
		case '.':
			flush()
		case '[':
			flush()
			j := i + 1
			for j < len(path) && path[j] != ']' {
				j++
			}
			if j < len(path) {
				segments = append(segments, "["+path[i+1:j]+"]")
				i = j
			} else {
				// Unterminated '[': keep the raw remainder as a segment so navigate
				// rejects it, instead of silently dropping the index and resolving
				// the parent (e.g. "choices[0" would otherwise return "choices").
				segments = append(segments, path[i:])
				i = len(path)
			}
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return segments
}

// navigate descends one segment into the decoded JSON value.
func navigate(data any, seg string) (any, error) {
	if strings.HasPrefix(seg, "[") && !strings.HasSuffix(seg, "]") {
		return nil, fmt.Errorf("websocket: malformed array index %q (missing ']')", seg)
	}
	if strings.HasPrefix(seg, "[") && strings.HasSuffix(seg, "]") {
		arr, ok := data.([]any)
		if !ok {
			return nil, fmt.Errorf("websocket: expected array for index %s", seg)
		}
		idx, err := strconv.Atoi(seg[1 : len(seg)-1])
		if err != nil {
			return nil, fmt.Errorf("websocket: invalid array index %s", seg)
		}
		if idx < 0 || idx >= len(arr) {
			return nil, fmt.Errorf("websocket: array index %d out of bounds", idx)
		}
		return arr[idx], nil
	}

	obj, ok := data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("websocket: expected object for field %q", seg)
	}
	val, ok := obj[seg]
	if !ok {
		return nil, fmt.Errorf("websocket: field %q not found", seg)
	}
	return val, nil
}

// valueToString renders a decoded JSON value as a string. Scalars convert
// directly; objects and arrays are re-marshaled to JSON.
func valueToString(val any) string {
	switch v := val.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	case nil:
		return ""
	default:
		data, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(data)
	}
}
