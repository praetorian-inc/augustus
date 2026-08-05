package mcptool

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// attWith builds a completed attempt whose prompt is the payload and whose output
// echoes it, the shape callOne produces against a real target.
func attWith(payload, output string) *attempt.Attempt {
	a := attempt.New(payload)
	a.AddOutput(output)
	a.Complete()
	return a
}

func bypassed(a *attempt.Attempt) bool {
	v, ok := a.GetMetadata(attempt.MetadataKeyPathTraversalGuardBypass)
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

// The verbatim DVMCP challenge 2 responses.
const (
	barePayload  = "../../../../../../etc/passwd"
	escPayload   = "/tmp/safe/../../../../../../etc/passwd"
	ctlPayload   = "/tmp/safe/augctl-0011223344556677"
	refusalTmpl  = "Error: Access to '%s' is not allowed. Only files in /tmp/safe/ are accessible."
	fsErrorTmpl  = "Error reading file: [Errno 2] No such file or directory: '%s'"
	passwdConten = "root:x:0:0:root:/root:/bin/bash\ndaemon:*:1:1::/:/usr/sbin/nologin"
)

func fmtResp(tmpl, payload string) string {
	// Deliberately not fmt.Sprintf-with-%s only: keep it explicit that the payload
	// is what varies between the three legs.
	out := ""
	for i := 0; i < len(tmpl); i++ {
		if i+1 < len(tmpl) && tmpl[i] == '%' && tmpl[i+1] == 's' {
			out += payload
			i++
			continue
		}
		out += string(tmpl[i])
	}
	return out
}

func TestMarkGuardBypass_DetectsBypassFromTheControlTriple(t *testing.T) {
	prefixed := attWith(escPayload, fmtResp(fsErrorTmpl, escPayload))
	baseline := attWith(barePayload, fmtResp(refusalTmpl, barePayload))
	control := attWith(ctlPayload, fmtResp(fsErrorTmpl, ctlPayload))

	markGuardBypass(prefixed, baseline, control)

	if !bypassed(prefixed) {
		t.Fatal("guard bypass not recorded: the guard refused the bare payload and accepted the escaped one")
	}
	// All three legs recorded so a reviewer can see the evidence, not just the verdict.
	if v, ok := prefixed.GetMetadata(attempt.MetadataKeyPathTraversalBaselineResponse); !ok || v == "" {
		t.Error("baseline response not recorded")
	}
	if v, ok := prefixed.GetMetadata(attempt.MetadataKeyPathTraversalControlResponse); !ok || v == "" {
		t.Error("control response not recorded")
	}
}

// TestMarkGuardBypass_IsPhraseAndLanguageIndependent is the point of the control
// triple. The oracle must not know what an authorization refusal or a filesystem
// error "looks like" — it compares outcome CLASSES, so a target that words its
// errors in another language, or as structured JSON, or terser than any English
// regex would match, is scored identically.
//
// An earlier implementation matched curated English phrases derived from one
// corpus of Python servers; every case below would have been silently missed.
func TestMarkGuardBypass_IsPhraseAndLanguageIndependent(t *testing.T) {
	cases := []struct {
		name    string
		refusal string
		fsErr   string
	}{
		{
			name:    "spanish prose",
			refusal: "Error: el acceso a '%s' no esta permitido.",
			fsErr:   "Error al leer el archivo: no existe '%s'",
		},
		{
			name:    "structured json",
			refusal: `{"error":{"code":-32001,"path":"%s"}}`,
			fsErr:   `{"error":{"code":-32003,"path":"%s"}}`,
		},
		{
			name:    "go style wrapped errors",
			refusal: "open %s: outside root",
			fsErr:   "open %s: file does not exist",
		},
		{
			name:    "terse and opaque",
			refusal: "DENIED %s",
			fsErr:   "MISSING %s",
		},
		{
			name:    "no wording at all, only a code",
			refusal: "4031 %s",
			fsErr:   "4041 %s",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prefixed := attWith(escPayload, fmtResp(tc.fsErr, escPayload))
			baseline := attWith(barePayload, fmtResp(tc.refusal, barePayload))
			control := attWith(ctlPayload, fmtResp(tc.fsErr, ctlPayload))

			markGuardBypass(prefixed, baseline, control)

			if !bypassed(prefixed) {
				t.Errorf("bypass not detected for %s wording; the oracle is still phrase-dependent", tc.name)
			}
		})
	}
}

func TestMarkGuardBypass_FalsePositiveGuards(t *testing.T) {
	t.Run("guard refused the escaped payload too", func(t *testing.T) {
		// Prefixing changed nothing: same class as the baseline.
		prefixed := attWith(escPayload, fmtResp(refusalTmpl, escPayload))
		baseline := attWith(barePayload, fmtResp(refusalTmpl, barePayload))
		control := attWith(ctlPayload, fmtResp(fsErrorTmpl, ctlPayload))

		markGuardBypass(prefixed, baseline, control)
		if bypassed(prefixed) {
			t.Error("recorded a bypass while the guard was still refusing")
		}
	})

	t.Run("target answers every path identically", func(t *testing.T) {
		// A server too terse to distinguish the classes must fail CLOSED rather
		// than have a bypass inferred from an indistinguishable response.
		same := "Error"
		prefixed := attWith(escPayload, same)
		baseline := attWith(barePayload, same)
		control := attWith(ctlPayload, same)

		markGuardBypass(prefixed, baseline, control)
		if bypassed(prefixed) {
			t.Error("inferred a bypass from responses that carry no distinction")
		}
	})

	t.Run("escaped payload landed somewhere the control did not", func(t *testing.T) {
		// Content came back: the traversal fully succeeded, which is the content
		// detector's 1.0 case, not this inconclusive path. Must not double-report.
		prefixed := attWith(escPayload, passwdConten)
		baseline := attWith(barePayload, fmtResp(refusalTmpl, barePayload))
		control := attWith(ctlPayload, fmtResp(fsErrorTmpl, ctlPayload))

		markGuardBypass(prefixed, baseline, control)
		if bypassed(prefixed) {
			t.Error("recorded a bypass for a response that did not match the accepted-control class")
		}
	})

	t.Run("control was itself refused", func(t *testing.T) {
		// The prefix does not actually satisfy the guard, so there is no evidence
		// the guard accepts anything under it.
		prefixed := attWith(escPayload, fmtResp(refusalTmpl, escPayload))
		baseline := attWith(barePayload, fmtResp(refusalTmpl, barePayload))
		control := attWith(ctlPayload, fmtResp(refusalTmpl, ctlPayload))

		markGuardBypass(prefixed, baseline, control)
		if bypassed(prefixed) {
			t.Error("recorded a bypass when the guard refused the in-sandbox control")
		}
	})

	t.Run("nil and empty legs are safe", func(t *testing.T) {
		prefixed := attWith(escPayload, fmtResp(fsErrorTmpl, escPayload))
		baseline := attWith(barePayload, fmtResp(refusalTmpl, barePayload))
		control := attWith(ctlPayload, fmtResp(fsErrorTmpl, ctlPayload))

		markGuardBypass(prefixed, baseline, nil)
		markGuardBypass(prefixed, nil, control)
		markGuardBypass(nil, baseline, control)
		markGuardBypass(prefixed, baseline, attWith(ctlPayload, ""))
		if bypassed(prefixed) {
			t.Error("recorded a bypass from a missing or empty leg")
		}
	})
}

func TestResponseTemplate_StripsOnlyTheEchoedPayload(t *testing.T) {
	// Two responses of the same class differing only in the echoed path must
	// reduce to the same template; different classes must not.
	a := attWith("/tmp/safe/one", "Error reading file: [Errno 2] No such file or directory: '/tmp/safe/one'")
	b := attWith("/tmp/safe/two", "Error reading file: [Errno 2] No such file or directory: '/tmp/safe/two'")
	c := attWith("/tmp/safe/two", "Error: Access to '/tmp/safe/two' is not allowed.")

	if responseTemplate(a) != responseTemplate(b) {
		t.Errorf("same class reduced differently:\n  %q\n  %q", responseTemplate(a), responseTemplate(b))
	}
	if responseTemplate(b) == responseTemplate(c) {
		t.Error("different classes reduced to the same template")
	}
	if responseTemplate(nil) != "" {
		t.Error("nil attempt should reduce to empty")
	}
}
