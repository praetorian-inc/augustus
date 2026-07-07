package recon

// ProbeContext carries shared assessment state gathered before probes run. It is
// delivered to probes that opt in via ContextAwareProbe, letting them reuse prior
// reconnaissance (e.g. an MCP tool inventory) instead of re-deriving it — the
// Metasploit model: recon populates a shared workspace, exploit modules read it.
type ProbeContext struct {
	// Recon is the shared observation store populated by the recon phase.
	// The runner always delivers a non-nil store (it may be empty).
	Recon *Store
}

// ContextAwareProbe is implemented by probes that consume prior reconnaissance.
// When a probe implements it, the runner calls SetContext exactly once before
// Probe(). Probes that do not implement it are unaffected and structurally
// cannot see recon — keeping the dependency explicit and opt-in.
type ContextAwareProbe interface {
	SetContext(ProbeContext)
}
