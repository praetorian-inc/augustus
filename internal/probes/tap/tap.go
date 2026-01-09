// Package tap provides TAP (Tree of Attacks with Pruning) probe for LLM testing.
//
// TAP implements tree-based attack generation that:
// 1. Generates adversarial prompts using a tree structure
// 2. Prunes ineffective branches based on scoring
// 3. Iteratively refines attacks based on model responses
//
// This package now loads probe definitions from YAML templates in the data/ directory.
// Probes are registered automatically via the init() function in templates.go.
//
// Historical note: This file previously contained hardcoded prompt constants
// (tapv1Prompt, tapv2Prompt) and SimpleProbe infrastructure. These were migrated
// to YAML templates following the Nuclei template pattern for community contributions.
package tap
