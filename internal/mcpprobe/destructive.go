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
	return destructiveToolNameRE.MatchString(name)
}
