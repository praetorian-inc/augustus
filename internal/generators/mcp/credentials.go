package mcp

import (
	"regexp"
	"sort"
	"strings"
)

// credentialHeaderNameRE matches request-header NAMES that conventionally carry
// caller credentials. It is deliberately a CONVENTIONAL vocabulary — names any
// practitioner would recognise as authentication material — and contains nothing
// specific to a particular server, product, or benchmark.
//
// It is matched against the header NAME only; values are never inspected, so no
// secret can influence the decision or leak into the result.
//
// Word-boundary anchoring (start/end or a -/_ separator) is what keeps it honest:
// it means "X-Api-Key" and "Authorization" match while "X-Tenant" does not merely
// because it contains the letters of no credential word, and "X-Forwarded-For"
// does not match on "for". Anchoring also prevents a bare substring hit such as
// "keep-alive" containing "ke".
var credentialHeaderNameRE = regexp.MustCompile(
	`(?i)(^|[-_])(authorization|auth|authentication|token|key|apikey|secret|credential|credentials|cookie|session|sessionid|password|passwd|bearer|jwt|access|subscription)($|[-_])`)

// isCredentialHeaderName reports whether a header name conventionally carries
// caller credentials. Exported within the package for direct testing of the
// vocabulary, so the conventional set is asserted rather than only exercised
// indirectly through generator construction.
func isCredentialHeaderName(name string) bool {
	return credentialHeaderNameRE.MatchString(name)
}

// ConfiguredCredentialHeaders implements the mcpprobe.CredentialReporter
// capability: it reports, by NAME only, which configured headers carry
// operator-supplied credential material for this target.
//
// A name is reported only when the header would actually reach the target
// carrying a secret. Two configurations are deliberately NOT reported, because
// both would let a probe assert an authentication boundary that was never
// established — turning an open server into a VULN verdict on a boundary the
// operator never configured:
//
//   - an empty / whitespace-only value; and
//   - a template whose only content is an unresolved "$KEY" with no api_key
//     configured. substituteHeader leaves "$KEY" literal in that case, so the
//     target receives the placeholder text rather than a credential.
//
// A "$VARNAME" hook-variable placeholder IS reported: hook variables are
// resolved per request and are not in scope when a probe asks, so assuming they
// resolve is the only choice that does not silently skip every
// hook-authenticated scan. Assuming otherwise would suppress the probe exactly
// where an auth boundary is most likely to exist.
func (m *MCP) ConfiguredCredentialHeaders() []string {
	out := make([]string, 0, len(m.cfg.Headers))
	for name, tmpl := range m.cfg.Headers {
		if !isCredentialHeaderName(name) {
			continue
		}
		if !m.headerCarriesSecret(tmpl) {
			continue
		}
		out = append(out, name)
	}
	// Sorted so attempt metadata and report output are stable across runs; Go's
	// map iteration order is randomised.
	sort.Strings(out)
	return out
}

// headerCarriesSecret reports whether a header template would reach the target
// carrying actual credential material.
func (m *MCP) headerCarriesSecret(tmpl string) bool {
	if strings.TrimSpace(tmpl) == "" {
		return false
	}
	// Strip the $KEY placeholder when no api_key backs it: what remains is the
	// literal prefix/suffix (e.g. "Bearer "), which is not a credential. If
	// something substantive remains — a hook var, or a literal secret alongside
	// the placeholder — the header still carries material.
	probe := tmpl
	if m.cfg.APIKey == "" {
		probe = strings.ReplaceAll(probe, "$KEY", "")
	}
	// A remaining "$" indicates a hook variable, which resolves per request.
	if strings.Contains(probe, "$") {
		return true
	}
	// Otherwise require a non-trivial literal. A scheme word alone ("Bearer",
	// "Basic", "Token") is not a secret.
	return !isSchemeOnly(probe)
}

// isSchemeOnly reports whether the remaining literal is nothing but an
// authentication scheme keyword and punctuation — i.e. carries no secret.
func isSchemeOnly(s string) bool {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return true
	}
	if len(fields) > 1 {
		return false
	}
	switch strings.ToLower(strings.Trim(fields[0], ":;,")) {
	case "bearer", "basic", "token", "digest", "apikey", "key":
		return true
	default:
		return false
	}
}
