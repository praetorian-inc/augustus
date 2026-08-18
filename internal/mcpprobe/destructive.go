package mcpprobe

import (
	"regexp"

	"github.com/praetorian-inc/augustus/pkg/types"
)

// destructiveToolNameRE matches tool names that conventionally denote an
// IRREVERSIBLE or state-destroying operation, as opposed to merely privileged
// ones. Whole segments only, so "resetter" does not match "reset".
var destructiveToolNameRE = regexp.MustCompile(
	`(?i)(^|[-_.])(delete|destroy|drop|remove|purge|erase|wipe|clear|truncate|revoke|disable|deactivate|shutdown|halt|stop|kill|terminate|restart|reboot|reset|format|uninstall|deprovision|unregister|deregister|detach|evict|expire|rotate|overwrite|replace|prune|clean|flush|rollback|downgrade)($|[-_.])`)

// mutatingToolNameRE matches names whose verbs conventionally CHANGE state without
// necessarily destroying it (create, update, grant, ...). It is broader than
// destructiveToolNameRE and exists for ONE purpose: deciding whether a tool is safe
// to invoke as a passive read-only PROOF, where any state change disqualifies it.
// It is deliberately NOT used to gate the authorization probes, which must still be
// able to test reversible privileged operations like grant_role or create_user.
var mutatingToolNameRE = regexp.MustCompile(
	`(?i)(^|[-_.])(create|update|modify|edit|write|store|save|set|put|patch|insert|add|append|send|post|publish|upload|grant|register|provision|assign|issue|generate|enable|activate|approve|submit|deploy|rename|move|copy|import|sync|apply|push)($|[-_.])`)

// camelBoundaryRE marks a lower/digit → upper transition — the word boundary in a
// camelCase identifier (resetPassword, apiKey, getOrCreateUser). The tool-name and
// credential-param vocabularies key off -_. separators, which camelCase omits, so a
// name is split here before matching or a camelCase target is silently unmatched.
var camelBoundaryRE = regexp.MustCompile(`([a-z0-9])([A-Z])`)

// SplitCamelCase inserts an underscore at each camelCase word boundary so a name
// written without separators still matches the -_.-anchored vocabularies.
func SplitCamelCase(s string) string {
	return camelBoundaryRE.ReplaceAllString(s, "${1}_${2}")
}

// ChangesStateByName reports whether a tool's NAME suggests invoking it would
// change state (mutate or destroy). Used to keep the read-only invocation proof
// from performing a write; handles camelCase.
func ChangesStateByName(name string) bool {
	n := SplitCamelCase(name)
	return destructiveToolNameRE.MatchString(n) || mutatingToolNameRE.MatchString(n)
}

// InvokesDestructiveOperation reports whether invoking this tool should be
// considered state-destroying in the ABSENCE of a definitive server annotation.
//
// This exists because internal/toolpolicy deliberately keeps unannotated tools:
// its documented rationale is that "a scanner's worst outcome is a silent false
// negative, and most servers ship no hints at all". That trade is right for a
// probe that sends a PAYLOAD to a tool — the payload is inert, and skipping the
// tool costs coverage for nothing.
//
// It is the wrong trade for a probe whose method IS invoking the privileged
// operation. There, "unknown" plus a name like `delete_user` or `shutdown_server`
// means the probe's own evidence-gathering is the damage. Measured: most real
// servers ship no annotations, so the unannotated case is the common case rather
// than the exception, and `mcptool.FunctionAuthorization`'s privileged-name
// vocabulary explicitly includes delete, shutdown, restart, revoke and exec.
//
// Precedence mirrors IsReadOnlyTool, inverted:
//
//	ReadOnly annotation      → not destructive (authoritative)
//	Destructive annotation    → destructive (authoritative)
//	no annotation + hit       → destructive (conservative)
//	no annotation + no hit    → not destructive
//
// A caller that wants the old behaviour opts in explicitly; the coverage lost is
// reported loudly rather than silently, so a narrowed sweep is never mistaken for
// a clean result.
func InvokesDestructiveOperation(tm map[string]any) bool {
	if ann, ok := tm["annotations"].(types.MCPToolAnnotations); ok {
		if ann.ReadOnly {
			return false
		}
		if ann.IsDestructive() {
			return true
		}
	}
	name, _ := tm["name"].(string)
	if name == "" {
		return false
	}
	return destructiveToolNameRE.MatchString(SplitCamelCase(name))
}
