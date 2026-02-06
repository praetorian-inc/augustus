// Package dan provides DAN (Do Anything Now) jailbreak probes for LLM testing.
//
// DAN probes attempt to get a target model to ignore its alignment and behave
// beyond its safety guardrails. These are community-developed prompts that use
// various techniques including roleplay, fictional scenarios, and social engineering.
//
// Only probes implementing a DAN attack or similar long-form instruction-based
// attack should be added here.
//
// All DAN probes are now defined as YAML templates in the data/ directory.
// See templates.go for automatic loading and registration.
package dan
