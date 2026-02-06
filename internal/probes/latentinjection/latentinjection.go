// Package latentinjection provides probes for testing latent injection attacks.
//
// Latent injection attacks involve hiding malicious instructions within seemingly
// benign text that only activate under certain conditions or in multi-turn conversations.
package latentinjection

// Probe registration is now handled by templates.go via YAML templates.
// The shared SimpleProbe implementation lives in pkg/probes/simple.go.
